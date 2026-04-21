// Case 03: static L2 forwarding controller.
//
// Pushes the pipeline, then writes four dmac table entries mapping
// 00:00:00:00:00:0{1..4} to switch ports 1..4. Runs until SIGTERM.
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

// macOfHost returns the well-known MAC of host hN in the 4-host topology.
func macOfHost(n int) string {
	return fmt.Sprintf("00:00:00:00:00:%02d", n)
}

func main() {
	var (
		addr   = flag.String("addr", "127.0.0.1:9559", "P4Runtime target address")
		p4info = flag.String("p4info", "", "path to p4info text proto (required)")
		config = flag.String("config", "", "path to BMv2 device config JSON (required)")
		dev    = flag.Uint64("device-id", 1, "device id")
		hosts  = flag.Int("hosts", 4, "number of hosts in the topology")
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

	tableName := "MyIngress.dmac"
	actionName := "MyIngress.forward"
	for n := 1; n <= *hosts; n++ {
		mac := macOfHost(n)
		entry, err := tableentry.NewBuilder(p, tableName).
			Match("hdr.ethernet.dstAddr", tableentry.Exact(codec.MustMAC(mac))).
			Action(actionName, tableentry.Param("egress_port", codec.MustEncodeUint(uint64(n), 9))).
			Build()
		if err != nil {
			log.Fatalf("build entry for %s: %v", mac, err)
		}
		if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			log.Fatalf("insert entry for %s: %v", mac, err)
		}
		log.Printf("dmac %s -> port %d installed", mac, n)
	}
	fmt.Printf("l2-forward ready: %d dmac entries installed\n", *hosts)

	<-ctx.Done()
	log.Println("shutting down")
}
