// Case 11: VXLAN encap controller.
//
// Single table, one action. When h1 sends a frame addressed to the
// inner MAC 00:00:00:11:11:11 (the "VTEP destination"), the switch
// wraps it in Outer Eth / IP / UDP / VXLAN(VNI=5000) and forwards to
// h2's port.
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

	// inner dst MAC 00:00:00:11:11:11 -> encap with VNI 5000
	entry, err := tableentry.NewBuilder(p, "MyIngress.vtep").
		Match("hdr.inner_eth.dstAddr", tableentry.Exact(codec.MustMAC("00:00:00:11:11:11"))).
		Action("MyIngress.encap",
			tableentry.Param("egress_port", codec.MustEncodeUint(2, 9)),
			tableentry.Param("outer_dmac", codec.MustMAC("00:00:00:00:00:02")),
			tableentry.Param("outer_smac", codec.MustMAC("00:00:00:de:ad:01")),
			tableentry.Param("outer_sip", codec.MustIPv4("192.168.1.1")),
			tableentry.Param("outer_dip", codec.MustIPv4("192.168.1.2")),
			tableentry.Param("vni", codec.MustEncodeUint(5000, 24)),
		).
		Build()
	if err != nil {
		log.Fatalf("build vtep entry: %v", err)
	}
	if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
		log.Fatalf("insert vtep entry: %v", err)
	}
	log.Printf("vtep: inner_dmac=00:00:00:11:11:11 -> encap vni=5000, port=2")

	fmt.Println("vxlan ready: 1 vtep entry installed")
	<-ctx.Done()
	log.Println("shutting down")
}
