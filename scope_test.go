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
