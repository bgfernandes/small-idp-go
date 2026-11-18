package issuer_test

import (
	"testing"

	"github.com/bgfernandes/small-idp-go/internal/issuer"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issuerString string
		wantErr      bool
	}{
		{name: "valid root issuer", issuerString: "http://localhost:8080", wantErr: false},
		{name: "valid https issuer", issuerString: "https://idp.example.com", wantErr: false},
		{
			name:         "valid issuer with path",
			issuerString: "https://idp.example.com/tenant",
			wantErr:      false,
		},
		{name: "empty string issuer", issuerString: "", wantErr: true},
		{name: "unparseable issuer", issuerString: "://bad", wantErr: true},
		{name: "no scheme issuer", issuerString: "idp.example.com", wantErr: true},
		{name: "wrong scheme issuer", issuerString: "ftp://idp.example.com", wantErr: true},
		{name: "no host issuer", issuerString: "http://", wantErr: true},
		{name: "issuer with query", issuerString: "http://idp.example.com?x=1", wantErr: true},
		{name: "issuer with fragment", issuerString: "http://idp.example.com#x=1", wantErr: true},
		{
			name:         "issuer with trailing slash",
			issuerString: "http://idp.example.com/",
			wantErr:      true,
		},
		{
			name:         "issuer with path and trailing slash",
			issuerString: "http://idp.example.com/tenant/",
			wantErr:      true,
		},
		{name: "issuer with trailing ?", issuerString: "http://idp.example.com?", wantErr: true},
		{name: "issuer with trailing #", issuerString: "http://idp.example.com#", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			i, err := issuer.Parse(tt.issuerString)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && i.String() != tt.issuerString {
				t.Errorf("String() = %v, want %v", i.String(), tt.issuerString)
			}
		})
	}
}

func TestMustParse(t *testing.T) {
	t.Parallel()

	i := issuer.MustParse("http://localhost:8080")
	if i.String() != "http://localhost:8080" {
		t.Errorf("MustParse() = %v, want %v", i.String(), "http://localhost:8080")
	}
}

func TestMustParsePanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("MustParse() did not panic")
		}
	}()
	issuer.MustParse("invalid")
}

func TestIsZero(t *testing.T) {
	t.Parallel()

	nonZeroIssuer, err := issuer.Parse("http://localhost:8080")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	tests := []struct {
		name string
		i    issuer.Issuer
		want bool
	}{
		{name: "zero issuer", i: issuer.Issuer{}, want: true},
		{name: "non-zero issuer", i: nonZeroIssuer, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.i.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issuerString string
		want         string
	}{
		{
			name:         "non-zero issuer",
			issuerString: "http://localhost:8080",
			want:         "http://localhost:8080",
		},
		{
			name:         "non-zero issuer with path",
			issuerString: "http://localhost:8080/path",
			want:         "http://localhost:8080/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			i, err := issuer.Parse(tt.issuerString)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got := i.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStringZeroIssuer(t *testing.T) {
	t.Parallel()

	i := issuer.Issuer{}
	if got := i.String(); got != "" {
		t.Errorf("String() = %v, want %v", got, "")
	}
}

func TestURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issuerString string
		elems        []string
		want         string
	}{
		{
			name:         "non-zero issuer",
			issuerString: "http://localhost:8080",
			elems:        []string{"api", "v1", "path"},
			want:         "http://localhost:8080/api/v1/path",
		},
		{
			name:         "non-zero issuer with path",
			issuerString: "http://localhost:8080/path",
			elems:        []string{"api", "v1", "path"},
			want:         "http://localhost:8080/path/api/v1/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			i, err := issuer.Parse(tt.issuerString)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got := i.URL(tt.elems...); got != tt.want {
				t.Errorf("URL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURLZeroIssuer(t *testing.T) {
	t.Parallel()

	i := issuer.Issuer{}
	if got := i.URL(); got != "" {
		t.Errorf("URL() = %v, want %v", got, "")
	}
}

func TestPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issuerString string
		elems        []string
		want         string
	}{
		{
			name:         "non-zero issuer",
			issuerString: "http://localhost:8080",
			elems:        []string{"api", "v1", "path"},
			want:         "/api/v1/path",
		},
		{
			name:         "non-zero issuer with path",
			issuerString: "http://localhost:8080/path",
			elems:        []string{"api", "v1", "path"},
			want:         "/path/api/v1/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			i, err := issuer.Parse(tt.issuerString)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got := i.Path(tt.elems...); got != tt.want {
				t.Errorf("Path() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPathZeroIssuer(t *testing.T) {
	t.Parallel()

	i := issuer.Issuer{}
	if got := i.Path(); got != "" {
		t.Errorf("Path() = %v, want %v", got, "")
	}
}
