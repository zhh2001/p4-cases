// Case 08: per-port packet counter reader.
//
// The P4 pipeline auto-increments `port_counter[ingress_port]` for
// every packet and cross-forwards port 1 <-> port 2 so the mininet
// hosts can actually exchange traffic. The controller pushes the
// pipeline, accepts a `dump` command on stdin (produced by the test
// script), and on each dump reads port_counter values for ports 1
// and 2 via the counter SDK, printing them back on stdout.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/counter"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
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

	r, err := counter.NewReader(c, p)
	if err != nil {
		log.Fatalf("counter reader: %v", err)
	}
	fmt.Println("counter ready; send 'dump' on stdin to print port_counter[1..2]")

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
		switch scanner.Text() {
		case "dump":
			for _, port := range []int64{1, 2} {
				readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
				entries, err := r.Read(readCtx, "MyIngress.port_counter", port)
				readCancel()
				if err != nil {
					fmt.Printf("ERR port %d: %v\n", port, err)
					continue
				}
				var pkts, bytes int64
				for _, e := range entries {
					pkts += e.Packets
					bytes += e.Bytes
				}
				fmt.Printf("port=%d packets=%d bytes=%d\n", port, pkts, bytes)
			}
			fmt.Println("dump-done")
		case "quit", "":
			return
		default:
			fmt.Printf("unknown command %q\n", scanner.Text())
		}
	}
}
