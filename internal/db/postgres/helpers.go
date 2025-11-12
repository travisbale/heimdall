package postgres

// stringToPointer converts a string to a *string pointer.
// Returns nil for empty strings to support nullable database columns.
func stringToPointer(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// pointerToString converts a *string pointer to a string.
// Returns empty string for nil pointers.
func pointerToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
