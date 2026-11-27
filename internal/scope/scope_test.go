package scope

import (
	"errors"
	"slices"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name          string
		s             string
		allowedScopes []string
		want          []string
		wantErr       error
	}{
		{
			name:          "unauthorized single scope",
			s:             "scope3",
			allowedScopes: []string{"scope1", "scope2"},
			wantErr:       errUnknownOrMalformedScope,
		},
		{
			name:          "unauthorized multiple scopes",
			s:             "scope3 scope4",
			allowedScopes: []string{"scope1", "scope2"},
			wantErr:       errUnknownOrMalformedScope,
		},
		{
			name:          "trailing space",
			s:             "scope1 ",
			allowedScopes: []string{"scope1", "scope2"},
			wantErr:       errUnknownOrMalformedScope,
		},
		{
			name:          "leading space",
			s:             " scope1",
			allowedScopes: []string{"scope1", "scope2"},
			wantErr:       errUnknownOrMalformedScope,
		},
		{
			name:          "leading and trailing space",
			s:             " scope1 ",
			allowedScopes: []string{"scope1", "scope2"},
			wantErr:       errUnknownOrMalformedScope,
		},
		{
			name:          "tab inside a scope",
			s:             "scope1\tscope2",
			allowedScopes: []string{"scope1", "scope2"},
			wantErr:       errUnknownOrMalformedScope,
		},
		{
			name:          "default scope",
			s:             "",
			allowedScopes: []string{"scope1", "scope2"},
			want:          []string{"scope1", "scope2"},
		},
		{
			name:          "single valid value",
			s:             "scope1",
			allowedScopes: []string{"scope1", "scope2"},
			want:          []string{"scope1"},
		},
		{
			name:          "duplicate scope",
			s:             "scope1 scope1",
			allowedScopes: []string{"scope1", "scope2"},
			want:          []string{"scope1"},
		},
		{
			name:          "scope order",
			s:             "scope2 scope1",
			allowedScopes: []string{"scope1", "scope2"},
			want:          []string{"scope2", "scope1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tt.s, tt.allowedScopes)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Parse(%q, %v) = %v, want %v", tt.s, tt.allowedScopes, err, tt.wantErr)
			}

			if tt.wantErr == nil {
				if !slices.Equal(got, tt.want) {
					t.Fatalf("Parse(%q, %v) = %v, want %v", tt.s, tt.allowedScopes, got, tt.want)
				}
			}
		})
	}
}
