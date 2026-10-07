package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func writeStatus(t *testing.T, codesToAttach ...codes.Code) error {
	t.Helper()
	response := status.New(codes.Unknown, "")
	for _, code := range codesToAttach {
		var err error
		response, err = response.WithDetails(&p4v1.Error{CanonicalCode: int32(code)})
		if err != nil {
			t.Fatal(err)
		}
	}
	return fmt.Errorf("write: %w", response.Err())
}

func TestUnsupportedRegisterWriteAcceptsOnlyExplicitUnimplementedErrors(t *testing.T) {
	for _, err := range []error{
		status.Error(codes.Unimplemented, "registers unavailable"),
		fmt.Errorf("write: %w", status.Error(codes.Unimplemented, "registers unavailable")),
		writeStatus(t, codes.Unimplemented),
	} {
		if !unsupportedRegisterWrite(err) {
			t.Fatalf("explicit unsupported response rejected: %v", err)
		}
	}
	for _, err := range []error{
		nil, errors.New("register missing from pipeline"),
		status.Error(codes.Unknown, "unimplemented"),
		status.Error(codes.PermissionDenied, "denied"),
		status.Error(codes.Unavailable, "connection lost"),
		status.Error(codes.DeadlineExceeded, "timeout"),
		writeStatus(t, codes.InvalidArgument),
		writeStatus(t, codes.Unimplemented, codes.Unimplemented),
		writeStatus(t, codes.Unimplemented, codes.PermissionDenied),
	} {
		if unsupportedRegisterWrite(err) {
			t.Fatalf("unrelated failure accepted as unsupported: %v", err)
		}
	}
}

func TestCommandsStopOnQuitBlankLineAndEOF(t *testing.T) {
	for _, input := range []string{"", "quit\n", " \n", " unknown \nquit\n", "unknown\n"} {
		var output bytes.Buffer
		if err := serveCommands(context.Background(), io.NopCloser(strings.NewReader(input)), &output); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(input, "unknown") && output.String() != "unknown command \"unknown\"\n" {
			t.Fatalf("unexpected command response: %q", output.String())
		}
	}
}

func TestCommandsRespondToCancellationWhileStdinIsIdle(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveCommands(ctx, reader, io.Discard) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle controller did not respond to cancellation")
	}
	if _, err := writer.Write([]byte("quit\n")); err == nil {
		t.Fatal("stdin reader remained open after cancellation")
	}
}

func TestCommandsReportInputAndOutputErrors(t *testing.T) {
	reader, writer := io.Pipe()
	want := errors.New("read failed")
	writer.CloseWithError(want)
	if err := serveCommands(context.Background(), reader, io.Discard); !errors.Is(err, want) {
		t.Fatalf("input failure: got %v", err)
	}
	if err := serveCommands(context.Background(), io.NopCloser(strings.NewReader("unknown\n")), failedWriter{}); err == nil {
		t.Fatal("output failure was ignored")
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("output failed") }
