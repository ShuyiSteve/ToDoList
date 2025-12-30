This project is a simple web-based Todo list with register/login, built with Vue on the frontend and
Cloudflare Workers + D1 on the backend for deployment.

## Structure
- `backend/` Go REST API (legacy local dev)
- `backend/sql/schema.sql` MySQL schema (legacy)
- `frontend/` Vue 3 single-page UI
- `worker/` Cloudflare Workers API (TypeScript)
- `worker/sql/schema.sql` D1 schema

## Backend setup (legacy Go + MySQL)
1. Create a MySQL database and apply the schema:
   ```sql
   SOURCE backend/sql/schema.sql;
   ```
2. Set environment variables:
   ```bash
   export DB_DSN="user:password@tcp(127.0.0.1:3306)/todolist?parseTime=true"
   export SERVER_ADDR=":8080"
   export TOKEN_TTL_HOURS="72"
   ```
3. Start the API:
   ```bash
   cd backend
   go run main.go
   ```

## Cloudflare Workers backend (D1)
1. Install dependencies:
   ```bash
   cd worker
   npm install
   ```
2. Create a D1 database:
   ```bash
   npx wrangler d1 create todolist-db
   ```
   Copy the `database_id` into `worker/wrangler.toml`.
3. Apply the schema:
   ```bash
   npx wrangler d1 execute todolist-db --file=sql/schema.sql
   ```
4. Local dev:
   ```bash
   npx wrangler dev
   ```
   The API will be available at `http://localhost:8787`.
5. Deploy:
   ```bash
   npx wrangler deploy
   ```

## Frontend setup (Vue + Vite)
1. Install dependencies:
   ```bash
   cd frontend
   npm install
   ```
2. Start the dev server:
   ```bash
   npm run dev
   ```
3. Open the URL printed in the terminal (usually `http://localhost:5173`).
4. Point the frontend at your deployed Worker by setting:
   ```bash
   VITE_API_BASE="https://your-worker.your-subdomain.workers.dev"
   ```

## API summary
- `POST /api/register` `{ "username": "", "password": "" }`
- `POST /api/login` `{ "username": "", "password": "" }` -> `{ "token": "" }`
- `GET /api/todos` (Bearer token)
- `POST /api/todos` `{ "title": "" }`
- `PUT /api/todos/:id` `{ "title": "", "done": true }`
- `DELETE /api/todos/:id`
