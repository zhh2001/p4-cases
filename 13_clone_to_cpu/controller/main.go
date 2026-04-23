// Case 13: clone-to-CPU controller.
//
// Installs a P4Runtime CloneSession 99 whose single replica is the
// BMv2 CPU port (510), then registers an OnPacketIn handler. Every
// packet the switch handles gets cloned; the egress pipeline stamps a
// cpu header (ethType=0x1010, next 16 bits = ingress_port). The
// controller counts arrivals and echoes each one to stdout so the
// topology driver can verify.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/pre"
)

const (
	cpuPort          = 510
	cloneSessionID   = 99
	expectedEthType  = 0x1010
	cpuHeaderLen     = 2  // our cpu_t is 16 bits
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

	// Install CloneSession 99 -> [cpu port]
	preW, err := pre.NewWriter(c)
	if err != nil {
		log.Fatalf("pre writer: %v", err)
	}
	if err := preW.InsertCloneSession(ctx, pre.CloneSession{
		ID:       cloneSessionID,
		Replicas: []pre.Replica{{EgressPort: cpuPort}},
	}); err != nil {
		log.Fatalf("install clone session: %v", err)
	}
	log.Printf("clone session %d -> cpu port %d installed", cloneSessionID, cpuPort)

	// Packet-in handler.
	var received int64
	c.OnPacketIn(func(_ context.Context, msg *p4v1.PacketIn) {
		payload := msg.GetPayload()
		n := atomic.AddInt64(&received, 1)
		// Parse: 14 bytes outer ether, 2 bytes cpu (ingress_port).
		if len(payload) < 14+cpuHeaderLen {
			log.Printf("#%d: short packet-in (%d bytes)", n, len(payload))
			return
		}
		ethType := binary.BigEndian.Uint16(payload[12:14])
		if ethType != expectedEthType {
			log.Printf("#%d: unexpected ethType 0x%04x (want 0x%04x)", n, ethType, expectedEthType)
			return
		}
		ingressPort := binary.BigEndian.Uint16(payload[14:16])
		fmt.Printf("packet-in #%d ingress_port=%d payload=%s\n", n, ingressPort,
			hex.EncodeToString(payload[:min(24, len(payload))]))
	})

	fmt.Println("clone-to-cpu ready")

	<-ctx.Done()
	log.Printf("shutting down; received %d packet-ins", atomic.LoadInt64(&received))
}
