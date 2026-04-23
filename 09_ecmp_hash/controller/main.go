// Case 09: ECMP controller.
//
// Topology: h1 (10.0.0.1) on port 1, h2 (10.0.0.2) on port 2,
// h3 (10.0.0.3) on port 3. ipv4_lpm for 10.0.0.0/24 hands control to
// a 2-member ECMP group; ecmp_nhop slot 0 -> port 2 (h2),
// slot 1 -> port 3 (h3). /32 routes to h2 and h3 themselves still
// exist as direct forwards so their own traffic doesn't re-enter
// ECMP.
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

	// Direct /32 routes for h1, h2, h3 so their own replies don't
	// re-enter ECMP.
	direct := []struct {
		ip, mac string
		port    uint64
	}{
		{"10.0.0.1", "00:00:00:00:00:01", 1},
		{"10.0.0.2", "00:00:00:00:00:02", 2},
		{"10.0.0.3", "00:00:00:00:00:03", 3},
	}
	for _, d := range direct {
		entry, err := tableentry.NewBuilder(p, "MyIngress.ipv4_lpm").
			Match("hdr.ipv4.dstAddr", tableentry.LPM(codec.MustIPv4(d.ip), 32)).
			Action("MyIngress.set_nhop",
				tableentry.Param("dstAddr", codec.MustMAC(d.mac)),
				tableentry.Param("port", codec.MustEncodeUint(d.port, 9))).
			Build()
		if err != nil {
			log.Fatalf("build direct %s: %v", d.ip, err)
		}
		if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			log.Fatalf("insert direct %s: %v", d.ip, err)
		}
		log.Printf("direct %s/32 -> port %d mac %s", d.ip, d.port, d.mac)
	}

	// ECMP group: any other 10.0.0.0/24 destination fans out between
	// h2 and h3 (two slots, base 0). Direct /32 above take priority
	// because LPM picks the longest prefix.
	ecmpEntry, err := tableentry.NewBuilder(p, "MyIngress.ipv4_lpm").
		Match("hdr.ipv4.dstAddr", tableentry.LPM(codec.MustIPv4("10.0.0.0"), 24)).
		Action("MyIngress.set_ecmp_select",
			tableentry.Param("ecmp_base", codec.MustEncodeUint(0, 14)),
			tableentry.Param("ecmp_count", codec.MustEncodeUint(2, 14))).
		Build()
	if err != nil {
		log.Fatalf("build ecmp entry: %v", err)
	}
	if err := c.WriteTableEntry(ctx, client.UpdateInsert, ecmpEntry); err != nil {
		log.Fatalf("insert ecmp entry: %v", err)
	}
	log.Printf("10.0.0.0/24 -> ecmp group(base=0, count=2)")

	// ECMP slots: 0 -> h2, 1 -> h3
	slots := []struct {
		idx  uint64
		mac  string
		port uint64
	}{
		{0, "00:00:00:00:00:02", 2},
		{1, "00:00:00:00:00:03", 3},
	}
	for _, s := range slots {
		entry, err := tableentry.NewBuilder(p, "MyIngress.ecmp_nhop").
			Match("meta.ecmp_select", tableentry.Exact(codec.MustEncodeUint(s.idx, 14))).
			Action("MyIngress.set_nhop",
				tableentry.Param("dstAddr", codec.MustMAC(s.mac)),
				tableentry.Param("port", codec.MustEncodeUint(s.port, 9))).
			Build()
		if err != nil {
			log.Fatalf("build ecmp slot %d: %v", s.idx, err)
		}
		if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			log.Fatalf("insert ecmp slot %d: %v", s.idx, err)
		}
		log.Printf("ecmp_nhop[%d] -> port %d mac %s", s.idx, s.port, s.mac)
	}

	fmt.Println("ecmp ready: 3 direct routes + 2-way ECMP group")
	<-ctx.Done()
	log.Println("shutting down")
}
