<template>
  <div class="scene">
    <div class="blob one"></div>
    <div class="blob two"></div>
    <div class="blob three"></div>
  </div>

  <div class="page" :class="{ 'page--focused': token }">
    <section class="hero" :class="{ compact: token }">
      <span v-if="!token" class="badge">Go + Vue + MySQL</span>
      <h1>Velvet List</h1>
      <p v-if="!token">
        A calm, focused space for your daily tasks. Register, sign in, and let your list sync
        across devices with a clean, modern workflow.
      </p>
      <div v-if="!token" class="pill">Data lives in MySQL - Sessions expire automatically</div>
    </section>

    <section v-if="!token" class="panel">
      <div class="tabs">
        <button class="tab" :class="{ active: mode === 'login' }" @click="mode = 'login'">
          Login
        </button>
        <button class="tab" :class="{ active: mode === 'register' }" @click="mode = 'register'">
          Register
        </button>
      </div>

      <div class="field">
        <label>Username</label>
        <input v-model.trim="authForm.username" placeholder="3-32 characters" />
      </div>
      <div class="field">
        <label>Password</label>
        <input v-model.trim="authForm.password" type="password" placeholder="6+ characters" />
      </div>

      <button class="primary" @click="submitAuth">
        {{ mode === "login" ? "Sign in" : "Create account" }}
      </button>
      <p v-if="message" :class="messageType">{{ message }}</p>
    </section>

    <section v-else class="panel todo-panel">
      <div class="todo-header">
        <div>
          <h2>Hello, {{ username }}</h2>
          <p class="pill">{{ todos.length }} task(s)</p>
        </div>
        <button class="ghost" @click="logout">Log out</button>
      </div>

      <div class="todo-input">
        <input v-model.trim="newTodo" placeholder="Add a new task" @keyup.enter="addTodo" />
        <button class="primary" @click="addTodo">Add task</button>
      </div>

      <div class="todo-list">
        <div v-for="todo in todos" :key="todo.id" class="todo-item" :class="{ done: todo.done }">
          <input type="checkbox" v-model="todo.done" @change="toggleTodo(todo)" />
          <span>{{ todo.title }}</span>
          <button class="ghost" @click="deleteTodo(todo)">Delete</button>
        </div>
      </div>

      <p v-if="message" :class="messageType">{{ message }}</p>
    </section>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from "vue";

const mode = ref("login");
const authForm = reactive({ username: "", password: "" });
const newTodo = ref("");
const todos = ref([]);
const token = ref(localStorage.getItem("token") || "");
const username = ref(localStorage.getItem("username") || "");
const message = ref("");
const messageType = ref("");

const apiBase = import.meta.env.VITE_API_BASE || "http://localhost:8787";

const showMessage = (text, type) => {
  message.value = text;
  messageType.value = type === "error" ? "error" : "success";
  setTimeout(() => {
    message.value = "";
  }, 3000);
};

const loadTodos = async () => {
  try {
    const res = await fetch(`${apiBase}/api/todos`, {
      headers: { Authorization: `Bearer ${token.value}` }
    });
    const data = await res.json();
    if (!res.ok) {
      showMessage(data.error || "Failed to load todos", "error");
      return;
    }
    todos.value = data;
  } catch (err) {
    showMessage("Network error", "error");
  }
};

const submitAuth = async () => {
  message.value = "";
  const endpoint = mode.value === "login" ? "/api/login" : "/api/register";
  try {
    const res = await fetch(apiBase + endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: authForm.username,
        password: authForm.password
      })
    });

    const data = await res.json();
    if (!res.ok) {
      showMessage(data.error || "Request failed", "error");
      return;
    }

    if (mode.value === "register") {
      showMessage("Account created. Please log in.", "success");
      mode.value = "login";
      return;
    }

    token.value = data.token;
    username.value = authForm.username;
    localStorage.setItem("token", token.value);
    localStorage.setItem("username", username.value);
    await loadTodos();
  } catch (err) {
    showMessage("Network error", "error");
  }
};

const addTodo = async () => {
  const title = newTodo.value.trim();
  if (!title) {
    showMessage("Please enter a title", "error");
    return;
  }
  try {
    const res = await fetch(`${apiBase}/api/todos`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token.value}`
      },
      body: JSON.stringify({ title })
    });
    const data = await res.json();
    if (!res.ok) {
      showMessage(data.error || "Failed to add todo", "error");
      return;
    }
    todos.value.unshift(data);
    newTodo.value = "";
  } catch (err) {
    showMessage("Network error", "error");
  }
};

const toggleTodo = async (todo) => {
  try {
    const res = await fetch(`${apiBase}/api/todos/${todo.id}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token.value}`
      },
      body: JSON.stringify({ done: todo.done })
    });
    if (!res.ok) {
      const data = await res.json();
      showMessage(data.error || "Failed to update todo", "error");
    }
  } catch (err) {
    showMessage("Network error", "error");
  }
};

const deleteTodo = async (todo) => {
  try {
    const res = await fetch(`${apiBase}/api/todos/${todo.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token.value}` }
    });
    if (!res.ok) {
      const data = await res.json();
      showMessage(data.error || "Failed to delete todo", "error");
      return;
    }
    todos.value = todos.value.filter((item) => item.id !== todo.id);
  } catch (err) {
    showMessage("Network error", "error");
  }
};

const logout = () => {
  token.value = "";
  username.value = "";
  todos.value = [];
  localStorage.removeItem("token");
  localStorage.removeItem("username");
  showMessage("Logged out", "success");
};

onMounted(() => {
  if (token.value) {
    loadTodos();
  }
});
</script>
