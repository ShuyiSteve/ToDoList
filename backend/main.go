package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type app struct {
	db       *sql.DB
	tokenTTL time.Duration
}

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

type todo struct {
	ID        int64     `json:"id"`
	Title     string    `json:"title"`
	Done      bool      `json:"done"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type createTodoRequest struct {
	Title string `json:"title"`
}

type updateTodoRequest struct {
	Title *string `json:"title"`
	Done  *bool   `json:"done"`
}

func main() {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		log.Fatal("DB_DSN is required")
	}

	ttlHours := 72
	if v := os.Getenv("TOKEN_TTL_HOURS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			ttlHours = parsed
		}
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	app := &app{db: db, tokenTTL: time.Duration(ttlHours) * time.Hour}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/register", app.withCORS(app.handleRegister))
	mux.HandleFunc("/api/login", app.withCORS(app.handleLogin))
	mux.HandleFunc("/api/todos", app.withCORS(app.handleTodos))
	mux.HandleFunc("/api/todos/", app.withCORS(app.handleTodoByID))

	addr := os.Getenv("SERVER_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

func (a *app) withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func (a *app) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := validateCredentials(req.Username, req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	_, err = a.db.Exec(`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, NOW())`, req.Username, string(hash))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			writeError(w, http.StatusConflict, "username already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := validateCredentials(req.Username, req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var userID int64
	var hash string
	row := a.db.QueryRow(`SELECT id, password_hash FROM users WHERE username = ?`, req.Username)
	if err := row.Scan(&userID, &hash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to login")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := generateToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	expiresAt := time.Now().Add(a.tokenTTL)
	_, err = a.db.Exec(`INSERT INTO sessions (user_id, token, expires_at, created_at) VALUES (?, ?, ?, NOW())`, userID, token, expiresAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{Token: token})
}

func (a *app) handleTodos(w http.ResponseWriter, r *http.Request) {
	userID, err := a.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := a.db.Query(`SELECT id, title, done, created_at, updated_at FROM todos WHERE user_id = ? ORDER BY created_at DESC`, userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load todos")
			return
		}
		defer rows.Close()

		todos := make([]todo, 0)
		for rows.Next() {
			var t todo
			if err := rows.Scan(&t.ID, &t.Title, &t.Done, &t.CreatedAt, &t.UpdatedAt); err != nil {
				writeError(w, http.StatusInternalServerError, "failed to load todos")
				return
			}
			todos = append(todos, t)
		}
		writeJSON(w, http.StatusOK, todos)
	case http.MethodPost:
		var req createTodoRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		title := strings.TrimSpace(req.Title)
		if title == "" {
			writeError(w, http.StatusBadRequest, "title is required")
			return
		}

		result, err := a.db.Exec(`INSERT INTO todos (user_id, title, done, created_at, updated_at) VALUES (?, ?, 0, NOW(), NOW())`, userID, title)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create todo")
			return
		}
		id, _ := result.LastInsertId()

		var t todo
		row := a.db.QueryRow(`SELECT id, title, done, created_at, updated_at FROM todos WHERE id = ? AND user_id = ?`, id, userID)
		if err := row.Scan(&t.ID, &t.Title, &t.Done, &t.CreatedAt, &t.UpdatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to fetch todo")
			return
		}
		writeJSON(w, http.StatusCreated, t)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) handleTodoByID(w http.ResponseWriter, r *http.Request) {
	userID, err := a.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	id, err := parseID(r.URL.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid todo id")
		return
	}

	switch r.Method {
	case http.MethodPut:
		var req updateTodoRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}

		fields := []string{}
		args := []any{}
		if req.Title != nil {
			title := strings.TrimSpace(*req.Title)
			if title == "" {
				writeError(w, http.StatusBadRequest, "title cannot be empty")
				return
			}
			fields = append(fields, "title = ?")
			args = append(args, title)
		}
		if req.Done != nil {
			fields = append(fields, "done = ?")
			args = append(args, *req.Done)
		}
		if len(fields) == 0 {
			writeError(w, http.StatusBadRequest, "no fields to update")
			return
		}
		fields = append(fields, "updated_at = NOW()")
		args = append(args, id, userID)

		query := fmt.Sprintf("UPDATE todos SET %s WHERE id = ? AND user_id = ?", strings.Join(fields, ", "))
		res, err := a.db.Exec(query, args...)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update todo")
			return
		}
		affected, _ := res.RowsAffected()
		if affected == 0 {
			writeError(w, http.StatusNotFound, "todo not found")
			return
		}

		var t todo
		row := a.db.QueryRow(`SELECT id, title, done, created_at, updated_at FROM todos WHERE id = ? AND user_id = ?`, id, userID)
		if err := row.Scan(&t.ID, &t.Title, &t.Done, &t.CreatedAt, &t.UpdatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to fetch todo")
			return
		}
		writeJSON(w, http.StatusOK, t)
	case http.MethodDelete:
		res, err := a.db.Exec(`DELETE FROM todos WHERE id = ? AND user_id = ?`, id, userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to delete todo")
			return
		}
		affected, _ := res.RowsAffected()
		if affected == 0 {
			writeError(w, http.StatusNotFound, "todo not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (a *app) authenticate(r *http.Request) (int64, error) {
	auth := r.Header.Get("Authorization")
	parts := strings.Fields(auth)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return 0, errors.New("missing auth token")
	}

	var userID int64
	row := a.db.QueryRow(`SELECT user_id FROM sessions WHERE token = ? AND expires_at > NOW()`, parts[1])
	if err := row.Scan(&userID); err != nil {
		return 0, errors.New("invalid or expired token")
	}

	return userID, nil
}

func generateToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validateCredentials(username, password string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 32 {
		return errors.New("username must be 3-32 characters")
	}
	if strings.Contains(username, " ") {
		return errors.New("username cannot contain spaces")
	}
	if len(password) < 6 || len(password) > 64 {
		return errors.New("password must be 6-64 characters")
	}
	return nil
}

func parseID(path string) (int64, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 {
		return 0, errors.New("invalid path")
	}
	return strconv.ParseInt(parts[len(parts)-1], 10, 64)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
