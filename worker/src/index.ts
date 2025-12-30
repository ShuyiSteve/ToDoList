interface Env {
  DB: D1Database;
  TOKEN_TTL_HOURS?: string;
}

const encoder = new TextEncoder();

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === "/api/register") {
        return await handleRegister(request, env);
      }
      if (path === "/api/login") {
        return await handleLogin(request, env);
      }
      if (path === "/api/todos") {
        return await handleTodos(request, env);
      }
      if (path.startsWith("/api/todos/")) {
        return await handleTodoById(request, env, path);
      }

      return jsonResponse({ error: "not found" }, 404);
    } catch (err) {
      return jsonResponse({ error: "server error" }, 500);
    }
  }
};

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS"
  };
}

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      ...corsHeaders(),
      "Content-Type": "application/json"
    }
  });
}

async function readJson<T>(request: Request): Promise<T> {
  const text = await request.text();
  if (!text) {
    throw new Error("empty body");
  }
  return JSON.parse(text) as T;
}

function validateCredentials(username: string, password: string): string | null {
  const trimmed = username.trim();
  if (trimmed.length < 3 || trimmed.length > 32) {
    return "username must be 3-32 characters";
  }
  if (trimmed.includes(" ")) {
    return "username cannot contain spaces";
  }
  if (password.length < 6 || password.length > 64) {
    return "password must be 6-64 characters";
  }
  return null;
}

async function handleRegister(request: Request, env: Env) {
  if (request.method !== "POST") {
    return jsonResponse({ error: "method not allowed" }, 405);
  }

  const body = await readJson<{ username: string; password: string }>(request);
  const error = validateCredentials(body.username, body.password);
  if (error) {
    return jsonResponse({ error }, 400);
  }

  const salt = generateToken(16);
  const hash = await hashPassword(body.password, salt);

  try {
    await env.DB.prepare(
      "INSERT INTO users (username, password_hash, password_salt) VALUES (?, ?, ?)"
    )
      .bind(body.username.trim(), hash, salt)
      .run();
  } catch (err) {
    const message = err instanceof Error ? err.message : "insert failed";
    if (message.toLowerCase().includes("unique")) {
      return jsonResponse({ error: "username already exists" }, 409);
    }
    return jsonResponse({ error: "failed to create user" }, 500);
  }

  return jsonResponse({ status: "ok" }, 201);
}

async function handleLogin(request: Request, env: Env) {
  if (request.method !== "POST") {
    return jsonResponse({ error: "method not allowed" }, 405);
  }

  const body = await readJson<{ username: string; password: string }>(request);
  const error = validateCredentials(body.username, body.password);
  if (error) {
    return jsonResponse({ error }, 400);
  }

  const user = await env.DB.prepare(
    "SELECT id, password_hash, password_salt FROM users WHERE username = ?"
  )
    .bind(body.username.trim())
    .first<{ id: number; password_hash: string; password_salt: string }>();

  if (!user) {
    return jsonResponse({ error: "invalid credentials" }, 401);
  }

  const hash = await hashPassword(body.password, user.password_salt);
  if (hash !== user.password_hash) {
    return jsonResponse({ error: "invalid credentials" }, 401);
  }

  const token = generateToken(32);
  const ttlHours = parseInt(env.TOKEN_TTL_HOURS || "72", 10);
  const expiresAt = Math.floor(Date.now() / 1000) + ttlHours * 3600;

  await env.DB.prepare(
    "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)"
  )
    .bind(user.id, token, expiresAt)
    .run();

  return jsonResponse({ token });
}

async function handleTodos(request: Request, env: Env) {
  const userId = await authenticate(request, env);
  if (!userId) {
    return jsonResponse({ error: "missing or invalid token" }, 401);
  }

  if (request.method === "GET") {
    const result = await env.DB.prepare(
      "SELECT id, title, done, created_at, updated_at FROM todos WHERE user_id = ? ORDER BY created_at DESC"
    )
      .bind(userId)
      .all<{ id: number; title: string; done: number; created_at: string; updated_at: string }>();

    const todos = (result.results || []).map((todo) => ({
      id: todo.id,
      title: todo.title,
      done: todo.done === 1,
      created_at: todo.created_at,
      updated_at: todo.updated_at
    }));

    return jsonResponse(todos);
  }

  if (request.method === "POST") {
    const body = await readJson<{ title: string }>(request);
    const title = body.title?.trim();
    if (!title) {
      return jsonResponse({ error: "title is required" }, 400);
    }

    const insert = await env.DB.prepare(
      "INSERT INTO todos (user_id, title, done) VALUES (?, ?, 0)"
    )
      .bind(userId, title)
      .run();

    const id = insert.meta?.last_row_id;
    const todo = await env.DB.prepare(
      "SELECT id, title, done, created_at, updated_at FROM todos WHERE id = ? AND user_id = ?"
    )
      .bind(id, userId)
      .first<{ id: number; title: string; done: number; created_at: string; updated_at: string }>();

    if (!todo) {
      return jsonResponse({ error: "failed to fetch todo" }, 500);
    }

    return jsonResponse(
      {
        id: todo.id,
        title: todo.title,
        done: todo.done === 1,
        created_at: todo.created_at,
        updated_at: todo.updated_at
      },
      201
    );
  }

  return jsonResponse({ error: "method not allowed" }, 405);
}

async function handleTodoById(request: Request, env: Env, path: string) {
  const userId = await authenticate(request, env);
  if (!userId) {
    return jsonResponse({ error: "missing or invalid token" }, 401);
  }

  const id = parseId(path);
  if (!id) {
    return jsonResponse({ error: "invalid todo id" }, 400);
  }

  if (request.method === "PUT") {
    const body = await readJson<{ title?: string; done?: boolean }>(request);
    const fields: string[] = [];
    const args: unknown[] = [];

    if (typeof body.title === "string") {
      const title = body.title.trim();
      if (!title) {
        return jsonResponse({ error: "title cannot be empty" }, 400);
      }
      fields.push("title = ?");
      args.push(title);
    }

    if (typeof body.done === "boolean") {
      fields.push("done = ?");
      args.push(body.done ? 1 : 0);
    }

    if (fields.length === 0) {
      return jsonResponse({ error: "no fields to update" }, 400);
    }

    fields.push("updated_at = CURRENT_TIMESTAMP");
    args.push(id, userId);

    const query = `UPDATE todos SET ${fields.join(", ")} WHERE id = ? AND user_id = ?`;
    const update = await env.DB.prepare(query).bind(...args).run();

    if (update.meta?.changes === 0) {
      return jsonResponse({ error: "todo not found" }, 404);
    }

    const todo = await env.DB.prepare(
      "SELECT id, title, done, created_at, updated_at FROM todos WHERE id = ? AND user_id = ?"
    )
      .bind(id, userId)
      .first<{ id: number; title: string; done: number; created_at: string; updated_at: string }>();

    if (!todo) {
      return jsonResponse({ error: "failed to fetch todo" }, 500);
    }

    return jsonResponse({
      id: todo.id,
      title: todo.title,
      done: todo.done === 1,
      created_at: todo.created_at,
      updated_at: todo.updated_at
    });
  }

  if (request.method === "DELETE") {
    const result = await env.DB.prepare("DELETE FROM todos WHERE id = ? AND user_id = ?")
      .bind(id, userId)
      .run();

    if (result.meta?.changes === 0) {
      return jsonResponse({ error: "todo not found" }, 404);
    }

    return jsonResponse({ status: "deleted" });
  }

  return jsonResponse({ error: "method not allowed" }, 405);
}

async function authenticate(request: Request, env: Env): Promise<number | null> {
  const auth = request.headers.get("Authorization") || "";
  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") {
    return null;
  }

  const token = parts[1];
  const now = Math.floor(Date.now() / 1000);
  const session = await env.DB.prepare(
    "SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?"
  )
    .bind(token, now)
    .first<{ user_id: number }>();

  return session?.user_id ?? null;
}

function parseId(path: string): number | null {
  const parts = path.split("/");
  const last = parts[parts.length - 1];
  const id = Number.parseInt(last, 10);
  return Number.isNaN(id) ? null : id;
}

function generateToken(size: number): string {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

async function hashPassword(password: string, salt: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, [
    "deriveBits"
  ]);
  const saltBytes = fromBase64Url(salt);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: 100000
    },
    key,
    256
  );
  return toBase64Url(new Uint8Array(bits));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(input: string): Uint8Array {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (padded.length % 4)) % 4;
  const normalized = padded + "=".repeat(padLength);
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
