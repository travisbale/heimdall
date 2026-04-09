//go:build integration

package test

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	var cleanup func()
	var err error

	harness, cleanup, err = setup(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to setup test harness: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	cleanup()
	os.Exit(code)
}
