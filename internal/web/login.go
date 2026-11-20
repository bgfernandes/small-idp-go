package web

import (
	"errors"
	"log/slog"
	"mime"
	"net/http"

	"github.com/bgfernandes/small-idp-go/internal/user"
)

type loginPageData struct {
	Action string
	Email  string
	Error  string
}

type successPageData struct {
	Email string
}

func (s *Server) writeLoginPage(w http.ResponseWriter, status int, email, errorMessage string) {
	s.writeHTMLTemplate(
		w,
		status,
		"login.html",
		loginPageData{
			Action: s.issuer.Path("login"),
			Email:  email,
			Error:  errorMessage,
		},
	)
}

func (s *Server) handleGetLogin(w http.ResponseWriter, _ *http.Request) {
	s.writeLoginPage(w, http.StatusOK, "", "")
}

const maxLoginRequestBytes = 1024 * 10 // 10KB

func (s *Server) handlePostLogin(w http.ResponseWriter, r *http.Request) {
	// Body type must be application/x-www-form-urlencoded
	mimeType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mimeType != "application/x-www-form-urlencoded" {
		s.writeLoginPage(w, http.StatusBadRequest, "", "Invalid content type.")
		return
	}

	// Parse body with a MaxBytesReader to limit the size of the request body
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginRequestBytes)
	if err := r.ParseForm(); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			s.writeLoginPage(w, http.StatusBadRequest, "", "Request body too large.")
			return
		}
		s.writeLoginPage(w, http.StatusBadRequest, "", "Invalid form encoding.")
		return
	}

	email := r.PostFormValue("email")
	password := r.PostFormValue("password")

	if email == "" || password == "" {
		s.writeLoginPage(w, http.StatusOK, email, "Unknown user or wrong password.")
		return
	}

	u, err := s.userAuthenticator.Authenticate(r.Context(), email, password)
	if err != nil {
		if errors.Is(err, user.ErrUnknownUserOrWrongPassword) {
			s.writeLoginPage(w, http.StatusOK, email, "Unknown user or wrong password.")
			return
		}
		s.log.Error("authenticate user", slog.Any("err", err))
		s.writeLoginPage(w, http.StatusInternalServerError, email, "Internal Server Error.")
		return
	}

	s.writeHTMLTemplate(
		w,
		http.StatusOK,
		"success.html",
		successPageData{Email: u.Email},
	)
}
