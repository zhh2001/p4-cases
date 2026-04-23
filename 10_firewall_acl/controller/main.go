// Case 10: firewall ACL controller.
//
// Installs a small L2 forwarding table and a set of TERNARY ACL rules
// with explicit priorities:
//
//   prio=100  DENY  any src -> 10.0.0.2, TCP, dport=22       (block SSH to h2)
//   prio= 90  ALLOW any src -> 10.0.0.2, TCP, any dport      (allow other TCP to h2)
//   prio= 80  DENY  10.0.0.1 -> any, UDP, dport=5000          (block a specific UDP flow)
//
// The acl table's default_action is `allow`, so anything not matched
// passes through.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
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

	// dmac: MAC -> port (same pattern as case 03).
	for n := 1; n <= 2; n++ {
		mac := fmt.Sprintf("00:00:00:00:00:%02d", n)
		entry, err := tableentry.NewBuilder(p, "MyIngress.dmac").
			Match("hdr.ethernet.dstAddr", tableentry.Exact(codec.MustMAC(mac))).
			Action("MyIngress.forward",
				tableentry.Param("egress_port", codec.MustEncodeUint(uint64(n), 9))).
			Build()
		if err != nil {
			log.Fatalf("build dmac: %v", err)
		}
		if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			log.Fatalf("insert dmac: %v", err)
		}
		log.Printf("dmac %s -> port %d", mac, n)
	}

	wildMask32 := []byte{0x00, 0x00, 0x00, 0x00} // all-zero mask == don't care
	exactMask32 := []byte{0xff, 0xff, 0xff, 0xff}
	exactMask8 := []byte{0xff}
	exactMask16 := []byte{0xff, 0xff}
	_ = wildMask32

	// Rule 1: highest priority DENY — TCP/22 to h2.
	rule1, err := tableentry.NewBuilder(p, "MyIngress.acl").
		Match("hdr.ipv4.srcAddr", tableentry.Ternary([]byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00, 0x00, 0x00})).
		Match("hdr.ipv4.dstAddr", tableentry.Ternary(codec.MustIPv4("10.0.0.2"), exactMask32)).
		Match("hdr.ipv4.protocol", tableentry.Ternary([]byte{6}, exactMask8)).
		Match("hdr.l4.dstPort", tableentry.Ternary(codec.MustEncodeUint(22, 16), exactMask16)).
		Action("MyIngress.deny").
		Priority(100).
		Build()
	if err != nil {
		log.Fatalf("build rule1: %v", err)
	}
	if err := c.WriteTableEntry(ctx, client.UpdateInsert, rule1); err != nil {
		log.Fatalf("insert rule1: %v", err)
	}
	log.Printf("acl rule p=100 DENY  * -> 10.0.0.2/32 TCP/22")

	// Rule 2: ALLOW any TCP to h2 (useful to demonstrate priority).
	rule2, err := tableentry.NewBuilder(p, "MyIngress.acl").
		Match("hdr.ipv4.srcAddr", tableentry.Ternary([]byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00, 0x00, 0x00})).
		Match("hdr.ipv4.dstAddr", tableentry.Ternary(codec.MustIPv4("10.0.0.2"), exactMask32)).
		Match("hdr.ipv4.protocol", tableentry.Ternary([]byte{6}, exactMask8)).
		Match("hdr.l4.dstPort", tableentry.Ternary([]byte{0x00, 0x00}, []byte{0x00, 0x00})).
		Action("MyIngress.allow").
		Priority(90).
		Build()
	if err != nil {
		log.Fatalf("build rule2: %v", err)
	}
	if err := c.WriteTableEntry(ctx, client.UpdateInsert, rule2); err != nil {
		log.Fatalf("insert rule2: %v", err)
	}
	log.Printf("acl rule p= 90 ALLOW * -> 10.0.0.2/32 TCP/any")

	// Rule 3: DENY one specific UDP flow.
	rule3, err := tableentry.NewBuilder(p, "MyIngress.acl").
		Match("hdr.ipv4.srcAddr", tableentry.Ternary(codec.MustIPv4("10.0.0.1"), exactMask32)).
		Match("hdr.ipv4.dstAddr", tableentry.Ternary([]byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00, 0x00, 0x00})).
		Match("hdr.ipv4.protocol", tableentry.Ternary([]byte{17}, exactMask8)).
		Match("hdr.l4.dstPort", tableentry.Ternary(codec.MustEncodeUint(5000, 16), exactMask16)).
		Action("MyIngress.deny").
		Priority(80).
		Build()
	if err != nil {
		log.Fatalf("build rule3: %v", err)
	}
	if err := c.WriteTableEntry(ctx, client.UpdateInsert, rule3); err != nil {
		log.Fatalf("insert rule3: %v", err)
	}
	log.Printf("acl rule p= 80 DENY  10.0.0.1/32 -> * UDP/5000")

	fmt.Println("firewall ready: 3 ACL rules installed")
	<-ctx.Done()
	log.Println("shutting down")
}
