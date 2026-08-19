package app

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// recorder notes the order in which shutdown touches each dependency.
type recorder struct {
	name  string
	calls *[]string
	err   error
}

func (r *recorder) ListenAndServe() error { return nil }

func (r *recorder) Shutdown(context.Context) error {
	*r.calls = append(*r.calls, r.name)
	return r.err
}

func (r *recorder) GracefulStop() { *r.calls = append(*r.calls, r.name) }

func (r *recorder) Close() { *r.calls = append(*r.calls, r.name) }

func shutdown(t *testing.T, drainErr error) ([]string, error) {
	t.Helper()
	var calls []string
	server := &Server{
		httpServer:  &recorder{name: "http", calls: &calls, err: drainErr},
		grpcServer:  &recorder{name: "grpc", calls: &calls},
		db:          &recorder{name: "db", calls: &calls},
		emailClient: &recorder{name: "email", calls: &calls},
	}
	return calls, server.Shutdown(context.Background())
}

// The ordering that makes shutdown graceful: both servers block until in-flight work
// returns, and that work is still querying, so releasing the pool first turns a clean
// deploy into a burst of 500s on requests that were about to succeed.
func TestShutdownDrainsBothServersBeforeClosingTheirDependencies(t *testing.T) {
	calls, err := shutdown(t, nil)
	if err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	db, http := slices.Index(calls, "db"), slices.Index(calls, "http")
	grpc, email := slices.Index(calls, "grpc"), slices.Index(calls, "email")
	if db < http || db < grpc {
		t.Errorf("shutdown order = %v, want the pool closed after both servers drained", calls)
	}
	if email < http || email < grpc {
		t.Errorf("shutdown order = %v, want the email client closed after both servers drained", calls)
	}
}

// A drain that times out must still release the pool.
func TestShutdownClosesDependenciesEvenIfDrainingFails(t *testing.T) {
	drainErr := errors.New("drain timed out")
	calls, err := shutdown(t, drainErr)

	if !errors.Is(err, drainErr) {
		t.Errorf("shutdown err = %v, want %v", err, drainErr)
	}
	for _, want := range []string{"db", "email"} {
		if !slices.Contains(calls, want) {
			t.Errorf("shutdown order = %v, want %s closed despite the drain failing", calls, want)
		}
	}
}
