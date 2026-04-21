// Case 06: In-band Network Telemetry (INT) controller.
//
// A single Go binary configures any of the three switches in the INT
// topology (s1, s2, s3), parameterised by -switch-id. Each switch gets:
//
//   * ipv4_lpm entries encoding the local view of the IPv4 routing
//     table (which dst subnet to send where, with which rewritten dst
//     MAC).
//   * ipv4_lpm default action set to drop (unknown destinations).
//   * int_table default action set to add_int_header(switch_id) so the
//     egress pipeline appends an INT trace stanza with this switch's
//     ID on every packet that already carries an INT option.
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

// lpmEntry models one row of ipv4_lpm. prefixLen is the LPM prefix
// length in bits.
type lpmEntry struct {
	cidr       string
	prefixLen  int32
	dstMAC     string
	egressPort uint64
}

// switchConfig bundles the per-switch INT configuration.
type switchConfig struct {
	deviceID uint64
	switchID uint64
	lpm      []lpmEntry
}

func configFor(switchID uint64) switchConfig {
	switch switchID {
	case 1:
		return switchConfig{
			deviceID: 1, switchID: 1,
			lpm: []lpmEntry{
				{"10.0.1.1", 32, "00:00:0a:00:01:01", 1},
				{"10.0.2.2", 32, "00:01:0a:00:02:02", 2},
				{"10.0.3.0", 24, "00:00:00:03:01:00", 3},
			},
		}
	case 2:
		return switchConfig{
			deviceID: 2, switchID: 2,
			lpm: []lpmEntry{
				{"10.0.2.2", 32, "00:00:0a:00:02:02", 1},
				{"10.0.0.0", 16, "00:00:00:01:02:00", 2},
			},
		}
	case 3:
		return switchConfig{
			deviceID: 3, switchID: 3,
			lpm: []lpmEntry{
				{"10.0.3.3", 32, "00:00:0a:00:03:03", 1},
				{"10.0.3.4", 32, "00:00:0a:00:03:04", 2},
				{"10.0.0.0", 16, "00:00:00:01:03:00", 3},
			},
		}
	default:
		log.Fatalf("unknown switch-id %d (expected 1|2|3)", switchID)
		return switchConfig{}
	}
}

func main() {
	var (
		addr     = flag.String("addr", "", "P4Runtime target address (required)")
		p4info   = flag.String("p4info", "", "path to p4info text proto (required)")
		config   = flag.String("config", "", "path to BMv2 device config JSON (required)")
		switchID = flag.Uint64("switch-id", 0, "switch id 1|2|3 (required)")
	)
	flag.Parse()
	if *addr == "" || *p4info == "" || *config == "" || *switchID == 0 {
		log.Fatal("-addr, -p4info, -config, -switch-id are required")
	}
	cfg := configFor(*switchID)

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
		client.WithDeviceID(cfg.deviceID),
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
	log.Printf("s%d: pipeline installed via %s", cfg.switchID, res.Action)

	// ipv4_lpm entries.
	for _, e := range cfg.lpm {
		entry, err := tableentry.NewBuilder(p, "MyIngress.ipv4_lpm").
			Match("hdr.ipv4.dstAddr",
				tableentry.LPM(codec.MustIPv4(e.cidr), e.prefixLen)).
			Action("MyIngress.ipv4_forward",
				tableentry.Param("dstAddr", codec.MustMAC(e.dstMAC)),
				tableentry.Param("port", codec.MustEncodeUint(e.egressPort, 9))).
			Build()
		if err != nil {
			log.Fatalf("build lpm entry %s/%d: %v", e.cidr, e.prefixLen, err)
		}
		if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			log.Fatalf("insert lpm entry %s/%d: %v", e.cidr, e.prefixLen, err)
		}
		log.Printf("s%d: lpm %s/%d -> port %d dst %s",
			cfg.switchID, e.cidr, e.prefixLen, e.egressPort, e.dstMAC)
	}

	// ipv4_lpm default action := drop.
	defDrop, err := tableentry.NewBuilder(p, "MyIngress.ipv4_lpm").
		AsDefault().
		Action("MyIngress.drop").
		Build()
	if err != nil {
		log.Fatalf("build ipv4_lpm default: %v", err)
	}
	if err := c.WriteTableEntry(ctx, client.UpdateModify, defDrop); err != nil {
		log.Fatalf("set ipv4_lpm default drop: %v", err)
	}

	// int_table default action := add_int_header(switch_id).
	defInt, err := tableentry.NewBuilder(p, "MyEgress.int_table").
		AsDefault().
		Action("MyEgress.add_int_header",
			tableentry.Param("swid", codec.MustEncodeUint(cfg.switchID, 13))).
		Build()
	if err != nil {
		log.Fatalf("build int_table default: %v", err)
	}
	if err := c.WriteTableEntry(ctx, client.UpdateModify, defInt); err != nil {
		log.Fatalf("set int_table default: %v", err)
	}
	log.Printf("s%d: int_table default = add_int_header(swid=%d)", cfg.switchID, cfg.switchID)

	fmt.Printf("s%d ready\n", cfg.switchID)
	<-ctx.Done()
	log.Printf("s%d shutting down", cfg.switchID)
}
