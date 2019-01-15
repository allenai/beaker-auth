package auth

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Permission is an access level for a resource.
type Permission string

const (
	// Read allows viewing a resource and its contents.
	Read Permission = "read"

	// Write allows Read and modification of a resource: create, edit, or delete.
	Write Permission = "write"

	// Admin allows Write and management of permissions.
	Admin Permission = "admin"
)

// Scope describes permission for a resource.
type Scope struct {
	// Permission level on a resource.
	Permission Permission

	// Class of resource for which permission is granted, such as "messages" or "files".
	Class string

	// (optional) Identifier for a specific resource within a class.
	Resource string
}

func (s *Scope) validate() error {
	const invalidChars = ": \r\n\t"

	switch s.Permission {
	case Read, Write, Admin:
		// OK.
	default:
		return errors.New("invalid permission")
	}

	if strings.ContainsAny(s.Class, invalidChars) {
		return fmt.Errorf("class %q contains invalid characters", s.Class)
	}
	if len(s.Class) == 0 {
		return errors.New("scope requires a resource class")
	}

	if strings.ContainsAny(s.Resource, invalidChars) {
		return fmt.Errorf("resource %q contains invalid characters", s.Resource)
	}

	return nil
}

func (s *Scope) String() string {
	str := string(s.Permission) + ":" + s.Class
	if s.Resource != "" {
		str += ":" + s.Resource
	}
	return str
}

// Parse a string-formatted Scope. This is the inverse of s.String().
func (s *Scope) parse(str string) error {
	parts := strings.SplitN(str, ":", 3)
	if len(parts) < 2 {
		return errors.New("invalid scope")
	}

	s.Permission = Permission(parts[0])
	s.Class = parts[1]
	if len(parts) > 2 {
		s.Resource = parts[2]
	}

	return s.validate()
}

// MarshalJSON implements the json.Marshaler interface.
func (s Scope) MarshalJSON() ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	return []byte(strconv.Quote(s.String())), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (s *Scope) UnmarshalJSON(b []byte) error {
	unquoted, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}
	return s.parse(unquoted)
}
