package web

import (
	"bytes"
	"log/slog"
	"net/http"
)

type loginPageData struct {
	Action string
	Email  string
	Error  string
}

func (s *Server) handleGetLogin(w http.ResponseWriter, _ *http.Request) {
	var buffer bytes.Buffer
	err := templates.ExecuteTemplate(
		&buffer,
		"login.html",
		loginPageData{Action: s.issuer.Path("login")},
	)
	if err != nil {
		s.log.Error("execute get login template", slog.Any("err", err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)

	_, err = buffer.WriteTo(w)
	if err != nil {
		s.log.Debug("write get login template", slog.Any("err", err))
	}
}
