package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/httpapi"
	"github.com/bgfernandes/small-idp-go/internal/jwk"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server failed", slog.Any("err", err))
		os.Exit(1)
	}
}

func run() error {
	cfg := loadConfig(os.Getenv)

	key, err := jwk.Generate()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	apiServer, err := httpapi.NewServer(cfg.issuer, key, slog.With("component", "HttpApi"))
	if err != nil {
		return fmt.Errorf("new server: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           apiServer.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Buffered channel to receive any errors from ListenAndServe
	listenAndServeErr := make(chan error, 1)

	slog.Info("server is starting", slog.String("addr", cfg.addr), slog.String("issuer", cfg.issuer))

	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			listenAndServeErr <- err
		}
	}()

	select {
	case err := <-listenAndServeErr:
		// ListenAndServe returned a non http.ErrServerClosed error
		return fmt.Errorf("listen and serve: %w", err)
	case <-ctx.Done():
		// Interrupt or SIGTERM received, gracefully shutdown the server
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}

		slog.Info("server shutdown")
		return nil
	}
}
