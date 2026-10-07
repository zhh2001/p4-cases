// Case 12: register-based flow counter controller.
//
// Installs the pipeline, demonstrates a register WRITE via the SDK's
// register package (pre-seeding slot 1023 with a sentinel value), and
// exposes a `quit` command on stdin.
//
// Targets may leave RegisterEntry unimplemented. Only an explicit
// UNIMPLEMENTED response permits skipping the seed. The topology uses
// simple_switch_CLI over Thrift to validate complete register snapshots.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/register"
)

func unsupportedRegisterWrite(err error) bool {
	response, ok := status.FromError(err)
	if !ok {
		return false
	}
	if response.Code() == codes.Unimplemented {
		return true
	}
	// P4Runtime reports per-update errors inside an UNKNOWN RPC status.
	if response.Code() != codes.Unknown {
		return false
	}
	details := response.Details()
	if len(details) != 1 {
		return false
	}
	item, ok := details[0].(*p4v1.Error)
	return ok && item.CanonicalCode == int32(codes.Unimplemented)
}

func serveCommands(ctx context.Context, input io.ReadCloser, output io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer input.Close()
	type command struct {
		line string
		err  error
	}
	commands := make(chan command)
	go func() {
		defer close(commands)
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			select {
			case commands <- command{line: scanner.Text()}:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			select {
			case commands <- command{err: err}:
			case <-ctx.Done():
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case item, ok := <-commands:
			if !ok {
				return nil
			}
			if item.err != nil {
				return item.err
			}
			line := strings.TrimSpace(item.line)
			if line == "" || line == "quit" {
				return nil
			}
			if _, err := fmt.Fprintf(output, "unknown command %q\n", line); err != nil {
				return err
			}
		}
	}
}

func main() {
	var (
		addr   = flag.String("addr", "127.0.0.1:9559", "P4Runtime target address")
		p4info = flag.String("p4info", "", "path to p4info text proto (required)")
		config = flag.String("config", "", "path to BMv2 device config JSON (required)")
		dev    = flag.Uint64("device-id", 1, "device id")
	)
	flag.Parse()
	if *p4info == "" || *config == "" {
		log.Fatal("-p4info and -config are required")
	}

	infoBytes, err := os.ReadFile(*p4info)
	if err != nil {
		log.Fatalf("read p4info: %v", err)
	}
	cfgBytes, err := os.ReadFile(*config)
	if err != nil {
		log.Fatalf("read device config: %v", err)
	}
	p, err := pipeline.LoadText(infoBytes, cfgBytes)
	if err != nil {
		log.Fatalf("parse pipeline: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	c, err := client.Dial(dialCtx, *addr,
		client.WithDeviceID(*dev),
		client.WithElectionID(client.ElectionID{Low: 1}),
		client.WithInsecure(),
	)
	if err != nil {
		log.Fatalf("dial %s: %v", *addr, err)
	}
	defer c.Close()
	if err := c.BecomePrimary(dialCtx); err != nil {
		log.Fatalf("arbitration: %v", err)
	}

	res, err := c.SetPipeline(ctx, p, client.SetPipelineOptions{})
	if err != nil {
		log.Fatalf("set pipeline: %v", err)
	}
	log.Printf("pipeline installed via %s", res.Action)

	// Demonstrate register.Write: initialise a distinguishing slot so
	// the thrift-side verifier can confirm control-plane writes
	// reached the data plane. Packet counts accumulate from this value.
	r, err := register.NewReader(c, p)
	if err != nil {
		log.Fatalf("register reader: %v", err)
	}
	writeCtx, writeCancel := context.WithTimeout(ctx, 3*time.Second)
	err = r.Write(writeCtx, "MyIngress.flow_counter", 1023, codec.MustEncodeUint(42, 32))
	writeCancel()
	if err != nil {
		if !unsupportedRegisterWrite(err) {
			log.Fatalf("seed register: %v", err)
		}
		log.Println("register seed skipped: RegisterEntry write is unimplemented")
	} else {
		log.Printf("seeded flow_counter[1023] = 42")
	}

	fmt.Println("register-counter ready")

	if err := serveCommands(ctx, os.Stdin, os.Stdout); err != nil {
		log.Fatalf("controller commands: %v", err)
	}
}
