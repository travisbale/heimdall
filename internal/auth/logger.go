package auth

type logger interface {
	Info(msg string, args ...any)
	Error(msg string, args ...any)
}
