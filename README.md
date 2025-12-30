This project is a simple web-based Todo list with register/login, built with Go + Vue + MySQL.

## Structure
- `backend/` Go REST API
- `backend/sql/schema.sql` MySQL schema
- `frontend/` Vue 3 single-page UI

## Backend setup
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

## API summary
- `POST /api/register` `{ "username": "", "password": "" }`
- `POST /api/login` `{ "username": "", "password": "" }` -> `{ "token": "" }`
- `GET /api/todos` (Bearer token)
- `POST /api/todos` `{ "title": "" }`
- `PUT /api/todos/:id` `{ "title": "", "done": true }`
- `DELETE /api/todos/:id`
