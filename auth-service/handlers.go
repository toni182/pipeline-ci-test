package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// =============================
// Estruturas
// =============================

// Estrutura para o corpo da requisição de criação de chave
type CreateKeyRequest struct {
	Name string `json:"name"`
}

// Estrutura para a resposta da criação de chave
type CreateKeyResponse struct {
	Name    string `json:"name"`
	Key     string `json:"key"` // Retornada apenas uma vez
	Message string `json:"message"`
}

// =============================
// Helpers
// =============================

// writeJSON escreve uma resposta JSON padronizada
func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("erro ao escrever response JSON: %v", err)
	}
}

// writeError padroniza erros em JSON
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}

// =============================
// Handlers
// =============================

// healthHandler é um simples endpoint de verificação de saúde
func (a *App) healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// validateKeyHandler verifica se uma chave de API (enviada via Header) é válida
func (a *App) validateKeyHandler(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")
	keyString := strings.TrimPrefix(authHeader, "Bearer ")

	if keyString == "" {
		writeError(w, http.StatusUnauthorized, "Authorization header não encontrado")
		return
	}

	keyHash := hashAPIKey(keyString)

	var id int
	err := a.DB.QueryRow(
		"SELECT id FROM api_keys WHERE key_hash = $1 AND is_active = true",
		keyHash,
	).Scan(&id)

	if err != nil {
		log.Printf("falha na validação da chave (hash: %s...): %v", keyHash[:6], err)
		writeError(w, http.StatusUnauthorized, "Chave de API inválida ou inativa")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Chave válida",
	})
}

// createKeyHandler cria uma nova chave de API
func (a *App) createKeyHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Método não permitido")
		return
	}

	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Corpo da requisição inválido")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "O campo 'name' é obrigatório")
		return
	}

	newKey, err := generateAPIKey()
	if err != nil {
		log.Printf("erro ao gerar chave: %v", err)
		writeError(w, http.StatusInternalServerError, "Erro ao gerar a chave")
		return
	}

	newKeyHash := hashAPIKey(newKey)

	var newID int
	err = a.DB.QueryRow(
		"INSERT INTO api_keys (name, key_hash) VALUES ($1, $2) RETURNING id",
		req.Name,
		newKeyHash,
	).Scan(&newID)

	if err != nil {
		log.Printf("erro ao salvar a chave no banco: %v", err)
		writeError(w, http.StatusInternalServerError, "Erro ao salvar a chave")
		return
	}

	log.Printf("nova chave criada com sucesso (ID: %d, Name: %s)", newID, req.Name)

	writeJSON(w, http.StatusCreated, CreateKeyResponse{
		Name:    req.Name,
		Key:     newKey,
		Message: "Guarde esta chave com segurança! Você não poderá vê-la novamente.",
	})
}

// =============================
// Middleware
// =============================

// masterKeyAuthMiddleware protege endpoints com MASTER_KEY
func (a *App) masterKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")
		keyString := strings.TrimPrefix(authHeader, "Bearer ")

		if keyString != a.MasterKey {
			writeError(w, http.StatusForbidden, "Acesso não autorizado")
			return
		}

		next.ServeHTTP(w, r)
	})
}
