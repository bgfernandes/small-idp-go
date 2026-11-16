package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/config"
	"github.com/bgfernandes/small-idp-go/internal/postgres"
	"github.com/bgfernandes/small-idp-go/internal/user"
)

type Store interface {
	Create(ctx context.Context, params user.CreateParams) (user.User, error)
}

var errUsage = errors.New("usage error")

const usageMessage = `usage: users <create>

create: create a new user
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageMessage)
		os.Exit(2)
	}

	if os.Args[1] == "--help" || os.Args[1] == "-h" {
		fmt.Fprint(os.Stderr, usageMessage)
		os.Exit(0)
	}

	if err := run(); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}

		if errors.Is(err, errUsage) {
			os.Exit(2)
		}

		invalidUserError, ok := errors.AsType[*user.InvalidUserError](err)
		if ok {
			fmt.Fprintln(os.Stderr, invalidUserError.Error())
			os.Exit(1)
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	switch os.Args[1] {
	case "create":
		return createUser(cfg)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		fmt.Fprint(os.Stderr, usageMessage)
		return errUsage
	}
}

func createUserStore(ctx context.Context, cfg config.Config) (Store, *sql.DB, error) {
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}

	store := postgres.NewUserStore(db, postgres.DefaultPasswordHashCost)

	return store, db, nil
}

func createUser(cfg config.Config) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)

	email := fs.String("email", "", "Email of the user")
	password := fs.String("password", "", "Password of the user")

	err := fs.Parse(os.Args[2:])
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store, db, err := createUserStore(ctx, cfg)
	if err != nil {
		return fmt.Errorf("create user store: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "close database:", err)
		}
	}()

	u, err := store.Create(ctx, user.CreateParams{
		Email:    *email,
		Password: *password,
	})
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	fmt.Println("User created successfully")
	fmt.Println("User ID:", u.ID)
	return nil
}
