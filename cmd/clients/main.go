package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bgfernandes/small-idp-go/internal/client"
	"github.com/bgfernandes/small-idp-go/internal/config"
	"github.com/bgfernandes/small-idp-go/internal/postgres"
)

type Store interface {
	Create(ctx context.Context, params client.CreateParams) (client.Client, string, error)
}

var errUsage = errors.New("usage error")

const usageMessage = `usage: clients <create>

create: create a new client
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

		invalidClientError, ok := errors.AsType[*client.InvalidClientError](err)
		if ok {
			fmt.Fprintln(os.Stderr, invalidClientError.Error())
			os.Exit(1)
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.Load(os.Getenv)

	switch os.Args[1] {
	case "create":
		return createClient(cfg)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		fmt.Fprint(os.Stderr, usageMessage)
		return errUsage
	}
}

func createPgStore(ctx context.Context, cfg config.Config) (Store, *sql.DB, error) {
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("open database: %w", err)
	}

	store := postgres.NewClientStore(db)

	return store, db, nil
}

type stringSliceVar []string

func (s *stringSliceVar) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (s *stringSliceVar) String() string {
	return strings.Join(*s, ", ")
}

func createClient(cfg config.Config) error {
	fs := flag.NewFlagSet("create", flag.ContinueOnError)

	var audiences stringSliceVar
	var grantTypes stringSliceVar
	var scopes stringSliceVar

	name := fs.String("name", "", "Name of the client")
	fs.Var(&audiences, "audience", "Audience of the client (can be repeated)")
	fs.Var(&grantTypes, "grant-type", "Grant type of the client (can be repeated)")
	fs.Var(&scopes, "scope", "Scope of the client (can be repeated)")

	err := fs.Parse(os.Args[2:])
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}

	typedGrantTypes := make([]client.GrantType, len(grantTypes))
	for i, v := range grantTypes {
		typedGrantTypes[i] = client.GrantType(v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	store, db, err := createPgStore(ctx, cfg)
	if err != nil {
		return fmt.Errorf("create pg store: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "close database:", err)
		}
	}()

	c, secret, err := store.Create(ctx, client.CreateParams{
		Name:       *name,
		Audiences:  audiences,
		GrantTypes: typedGrantTypes,
		Scopes:     scopes,
	})
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	fmt.Println("Client created successfully")
	fmt.Println("Client ID:", c.ID)
	fmt.Println("Client Secret:", secret)
	return nil
}
