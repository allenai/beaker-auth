package auth

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshalScope(t *testing.T) {
	tests := map[string]struct {
		Input       Scope
		Expected    string
		ExpectedErr string
	}{
		"Empty": {
			ExpectedErr: "json: error calling MarshalJSON for type auth.Scope: invalid permission",
		},
		"InvalidPermission": {
			Input:       Scope{Permission: Permission("notathing"), Class: "class"},
			ExpectedErr: "json: error calling MarshalJSON for type auth.Scope: invalid permission",
		},
		"MissingClass": {
			Input:       Scope{Permission: Admin},
			ExpectedErr: "json: error calling MarshalJSON for type auth.Scope: scope requires a resource class",
		},
		"InvalidClass": {
			Input:       Scope{Permission: Admin, Class: "white space"},
			ExpectedErr: `json: error calling MarshalJSON for type auth.Scope: class "white space" contains invalid characters`,
		},
		"InvalidResource": {
			Input:       Scope{Permission: Admin, Class: "class", Resource: "extra:colon"},
			ExpectedErr: `json: error calling MarshalJSON for type auth.Scope: resource "extra:colon" contains invalid characters`,
		},
		"ClassOnly": {
			Input:    Scope{Permission: Read, Class: "foo"},
			Expected: `"read:foo"`,
		},
		"SpecificResource": {
			Input:    Scope{Permission: Write, Class: "a", Resource: "b"},
			Expected: `"write:a:b"`,
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		b, err := json.Marshal(test.Input)
		if test.ExpectedErr != "" {
			assert.EqualError(t, err, test.ExpectedErr)
			continue
		}

		assert.NoError(t, err)
		assert.Equal(t, test.Expected, string(b))
	}
}

func TestUnmarshalScope(t *testing.T) {
	tests := map[string]struct {
		Input       string
		Expected    Scope
		ExpectedErr string
	}{
		"Nil": {
			ExpectedErr: "unexpected end of JSON input",
		},
		"Empty": {
			ExpectedErr: "unexpected end of JSON input",
		},
		"InvalidPermission": {
			Input:       `"notathing:class"`,
			ExpectedErr: "invalid permission",
		},
		"MissingClass": {
			Input:       `"admin:"`,
			ExpectedErr: "scope requires a resource class",
		},
		"InvalidClass": {
			Input:       `"admin:white space"`,
			ExpectedErr: `class "white space" contains invalid characters`,
		},
		"InvalidResource": {
			Input:       `"admin:class:extra:colon"`,
			ExpectedErr: `resource "extra:colon" contains invalid characters`,
		},
		"ClassOnly": {
			Input:    `"read:foo"`,
			Expected: Scope{Permission: Read, Class: "foo"},
		},
		"SpecificResource": {
			Input:    `"write:a:b"`,
			Expected: Scope{Permission: Write, Class: "a", Resource: "b"},
		},
	}

	for name, test := range tests {
		t.Logf("Running test case: %s", name)

		var result Scope
		err := json.Unmarshal([]byte(test.Input), &result)
		if test.ExpectedErr != "" {
			assert.EqualError(t, err, test.ExpectedErr)
			continue
		}

		assert.NoError(t, err)
		assert.Equal(t, test.Expected, result)
	}
}

func TestScopeAllows(t *testing.T) {
	tests := []struct {
		Allowed  Scope
		Target   Scope
		Expected bool
	}{
		// Different class
		{Allowed: Scope{Read, "a", ""}, Target: Scope{Read, "b", "other"}, Expected: false},

		// Different resource
		{Allowed: Scope{Read, "a", "b"}, Target: Scope{Read, "a", "other"}, Expected: false},

		// Allow full class
		{Allowed: Scope{Read, "a", ""}, Target: Scope{Read, "a", "other"}, Expected: true},

		// Allow read
		{Allowed: Scope{Read, "a", "b"}, Target: Scope{Read, "a", "b"}, Expected: true},
		{Allowed: Scope{Read, "a", "b"}, Target: Scope{Write, "a", "b"}, Expected: false},
		{Allowed: Scope{Read, "a", "b"}, Target: Scope{Admin, "a", "b"}, Expected: false},

		// Allow write
		{Allowed: Scope{Write, "a", "b"}, Target: Scope{Read, "a", "b"}, Expected: true},
		{Allowed: Scope{Write, "a", "b"}, Target: Scope{Write, "a", "b"}, Expected: true},
		{Allowed: Scope{Write, "a", "b"}, Target: Scope{Admin, "a", "b"}, Expected: false},

		// Allow admin
		{Allowed: Scope{Admin, "a", "b"}, Target: Scope{Read, "a", "b"}, Expected: true},
		{Allowed: Scope{Admin, "a", "b"}, Target: Scope{Write, "a", "b"}, Expected: true},
		{Allowed: Scope{Admin, "a", "b"}, Target: Scope{Admin, "a", "b"}, Expected: true},
	}

	for _, test := range tests {
		assert.Equal(t, test.Expected, test.Allowed.Allows(test.Target), "Allowed: %s, Target: %s", test.Allowed.String(), test.Target.String())
	}
}
