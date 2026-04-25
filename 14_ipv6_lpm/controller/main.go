// Case 14: IPv6 LPM controller.
//
// Installs four entries in MyIngress.ipv6_lpm:
//
//   2001:db8:1::/64    -> port 1, dstMac 00:00:00:00:00:01 (h1)
//   2001:db8:2::/64    -> port 2, dstMac 00:00:00:00:00:02 (h2)
//   2001:db8:3::/64    -> port 3, dstMac 00:00:00:00:00:03 (h3)
//   2001:db8:3::1/128  -> port 3, dstMac 00:00:00:00:00:03 (h3)
//
// The /128 entry is intentionally a duplicate-by-next-hop of the /64
// it shadows — its only purpose is to demonstrate that BMv2 hits the
// longer prefix first when multiple LPM entries match.
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

type route struct {
	prefix    string
	prefixLen int32
	dstMac    string
	port      uint64
	desc      string
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

	routes := []route{
		{"2001:db8:1::", 64, "00:00:00:00:00:01", 1, "h1 /64"},
		{"2001:db8:2::", 64, "00:00:00:00:00:02", 2, "h2 /64"},
		{"2001:db8:3::", 64, "00:00:00:00:00:03", 3, "h3 /64"},
		{"2001:db8:3::1", 128, "00:00:00:00:00:03", 3, "h3 /128 (more specific)"},
	}

	for _, r := range routes {
		entry, err := tableentry.NewBuilder(p, "MyIngress.ipv6_lpm").
			Match("hdr.ipv6.dstAddr", tableentry.LPM(codec.MustIPv6(r.prefix), r.prefixLen)).
			Action("MyIngress.ipv6_forward",
				tableentry.Param("dstMac", codec.MustMAC(r.dstMac)),
				tableentry.Param("port", codec.MustEncodeUint(r.port, 9))).
			Build()
		if err != nil {
			log.Fatalf("build %s: %v", r.desc, err)
		}
		if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			log.Fatalf("insert %s: %v", r.desc, err)
		}
		log.Printf("ipv6_lpm  %s/%d -> port %d, dmac %s  (%s)",
			r.prefix, r.prefixLen, r.port, r.dstMac, r.desc)
	}

	fmt.Println("ipv6 router ready: 4 LPM routes installed")
	<-ctx.Done()
	log.Println("shutting down")
}
