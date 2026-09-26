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
)

func main() {
	if err := run(); err != nil {
		slog.Error("server failed", slog.Any("err", err))
		os.Exit(1)
	}
}

func run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello, world"))
	})

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Buffered channel to receive any errors from ListenAndServe
	listenAndServeErr := make(chan error, 1)

	slog.Info("server is starting", slog.String("addr", srv.Addr))

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
