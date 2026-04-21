// Case 07: meter controller.
//
// The indirect meter pipeline maps an ethernet src MAC to a meter index
// in `m_read`, invokes the meter to colour the packet (green=0,
// yellow=1, red=2), then `m_filter` drops anything coloured other than
// green. Packets whose src MAC is not in `m_read` skip the meter and
// stay green, so they always pass.
//
// The controller installs:
//   * m_read entry mapping the "metered" src MAC to meter index 0
//   * m_filter entry matching tag=0 -> NoAction (pass)
//   * a MeterEntry configuring index 0 with a tight CIR so bursty
//     traffic turns red and gets dropped.
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
	"github.com/zhh2001/p4runtime-go-controller/meter"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
)

const (
	meteredMAC = "aa:aa:aa:aa:aa:aa"
	meterIndex = 0
)

func main() {
	var (
		addr   = flag.String("addr", "127.0.0.1:9559", "P4Runtime target address")
		p4info = flag.String("p4info", "", "path to p4info text proto (required)")
		config = flag.String("config", "", "path to BMv2 device config JSON (required)")
		dev    = flag.Uint64("device-id", 1, "device id")
		cir    = flag.Int64("cir", 10, "committed information rate (packets/sec)")
		cburst = flag.Int64("cburst", 5, "committed burst size (packets)")
		pir    = flag.Int64("pir", 20, "peak information rate (packets/sec)")
		pburst = flag.Int64("pburst", 10, "peak burst size (packets)")
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

	// m_read: src MAC aa:aa:aa:aa:aa:aa -> m_action(meter_index=0)
	readEntry, err := tableentry.NewBuilder(p, "MyIngress.m_read").
		Match("hdr.ethernet.srcAddr", tableentry.Exact(codec.MustMAC(meteredMAC))).
		Action("MyIngress.m_action",
			tableentry.Param("meter_index", codec.MustEncodeUint(meterIndex, 32))).
		Build()
	if err != nil {
		log.Fatalf("build m_read entry: %v", err)
	}
	if err := c.WriteTableEntry(ctx, client.UpdateInsert, readEntry); err != nil {
		log.Fatalf("insert m_read: %v", err)
	}
	log.Printf("m_read: src=%s -> m_action(index=%d)", meteredMAC, meterIndex)

	// m_filter: meter_tag 0 (green) -> NoAction; default drops non-zero tags.
	filterEntry, err := tableentry.NewBuilder(p, "MyIngress.m_filter").
		Match("meta.meter_tag", tableentry.Exact(codec.MustEncodeUint(0, 32))).
		Action("NoAction").
		Build()
	if err != nil {
		log.Fatalf("build m_filter entry: %v", err)
	}
	if err := c.WriteTableEntry(ctx, client.UpdateInsert, filterEntry); err != nil {
		log.Fatalf("insert m_filter: %v", err)
	}
	log.Printf("m_filter: tag=0 -> NoAction (non-zero tags drop via default)")

	// Configure the meter at index 0.
	mr, err := meter.NewReader(c, p)
	if err != nil {
		log.Fatalf("meter reader: %v", err)
	}
	if err := mr.Write(ctx, "MyIngress.my_meter", meterIndex, meter.Config{
		CIR: *cir, CBurst: *cburst, PIR: *pir, PBurst: *pburst,
	}); err != nil {
		log.Fatalf("configure meter: %v", err)
	}
	log.Printf("meter[%d]: CIR=%d cburst=%d PIR=%d pburst=%d",
		meterIndex, *cir, *cburst, *pir, *pburst)

	fmt.Printf("meter-switch ready: metered src=%s, cburst=%d packets\n", meteredMAC, *cburst)
	<-ctx.Done()
	log.Println("shutting down")
}
