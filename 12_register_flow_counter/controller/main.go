// Case 12: register-based flow counter — controller side.
//
// Installs the pipeline, demonstrates a register WRITE via the SDK's
// register package (pre-seeding slot 0 with a sentinel value so you
// can verify round-tripping), and exposes a `quit` command on stdin.
//
// NOTE: BMv2's P4Runtime server currently returns Unimplemented for
// register READS (RegisterEntry with index set and empty data). The
// companion run.sh uses `simple_switch_CLI` over Thrift to read back
// register values for verification — the P4 data-plane code itself is
// the same story regardless of how the control plane peeks at state.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/register"
)

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
	// reached the data plane. BMv2 will later overwrite this slot if
	// a packet happens to hash there; we just want one round-trip.
	r, err := register.NewReader(c, p)
	if err != nil {
		log.Fatalf("register reader: %v", err)
	}
	if err := r.Write(ctx, "MyIngress.flow_counter", 1023, codec.MustEncodeUint(42, 32)); err != nil {
		log.Printf("warn: register write not accepted by BMv2 (%v) — continuing", err)
	} else {
		log.Printf("seeded flow_counter[1023] = 42")
	}

	fmt.Println("register-counter ready")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !scanner.Scan() {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		switch line {
		case "", "quit":
			return
		default:
			fmt.Printf("unknown command %q\n", line)
		}
	}
}
