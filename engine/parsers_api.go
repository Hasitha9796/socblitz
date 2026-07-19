package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// parsers_api.go — management API for CBN parsers (list / view / create / edit /
// delete). Custom parsers are validated (must compile), persisted in ClickHouse,
// and hot-reloaded into the active set through the ParserStore.

// GET /parsers      → list every active parser (metadata + editable YAML)
// POST /parsers     → create or update a parser (body: {"yaml": "..."} )
func (s *Server) handleParsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.parsers.List())
	case http.MethodPost:
		s.upsertParser(w, r)
	default:
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
	}
}

// GET    /parsers/{name} → one parser
// PUT    /parsers/{name} → update (body: {"yaml": "..."} ; yaml's name must match)
// DELETE /parsers/{name} → delete a custom parser
func (s *Server) handleParserByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/parsers/")
	if name == "" {
		http.Error(w, "parser name required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		info, ok := s.parsers.Get(name)
		if !ok {
			http.Error(w, "parser not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, info)
	case http.MethodPut:
		s.upsertParser(w, r)
	case http.MethodDelete:
		if err := s.parsers.Delete(r.Context(), name); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
	default:
		http.Error(w, "GET, PUT or DELETE", http.StatusMethodNotAllowed)
	}
}

func (s *Server) upsertParser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.YAML) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "empty parser YAML"})
		return
	}
	info, err := s.parsers.Upsert(context.Background(), req.YAML)
	if err != nil {
		// 200 with an error field so the UI can show the validation message
		// inline (same convention as the /parser/test endpoint).
		writeJSON(w, http.StatusOK, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": info})
}
