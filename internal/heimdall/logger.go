package heimdall

type logger interface {
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Error(msg string, ctx ...interface{})
}
