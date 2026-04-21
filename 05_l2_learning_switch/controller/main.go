// Case 05: L2 MAC learning switch controller (digest variant).
//
// Flow:
//
//   1. Push the pipeline.
//   2. Install multicast groups 1..N and broadcast table entries so
//      frames with unknown destinations flood to every port except
//      the ingress.
//   3. Subscribe to the `learn_t` digest. Every time BMv2 sees a
//      source MAC it has not seen before, it fires a digest carrying
//      (srcAddr, ingress_port). The controller installs matching
//      smac (source seen) + dmac (where to forward) entries so the
//      next frame reuses them instead of re-triggering the digest
//      and/or flooding.
//   4. Sleep until SIGTERM.
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
	"sync"
	"syscall"
	"time"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/digest"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/pre"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
)

func main() {
	var (
		addr   = flag.String("addr", "127.0.0.1:9559", "P4Runtime target address")
		p4info = flag.String("p4info", "", "path to p4info text proto (required)")
		config = flag.String("config", "", "path to BMv2 device config JSON (required)")
		dev    = flag.Uint64("device-id", 1, "device id")
		ports  = flag.Int("ports", 4, "number of switch ports (= hosts)")
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

	// Multicast groups: group P = every port except P.
	preW, err := pre.NewWriter(c)
	if err != nil {
		log.Fatalf("pre writer: %v", err)
	}
	for ingress := 1; ingress <= *ports; ingress++ {
		replicas := make([]pre.Replica, 0, *ports-1)
		for q := 1; q <= *ports; q++ {
			if q == ingress {
				continue
			}
			replicas = append(replicas, pre.Replica{EgressPort: uint32(q)})
		}
		if err := preW.InsertMulticastGroup(ctx, pre.MulticastGroup{
			ID:       uint32(ingress),
			Replicas: replicas,
		}); err != nil {
			log.Fatalf("insert mcast group %d: %v", ingress, err)
		}
	}
	log.Printf("installed %d multicast groups", *ports)

	// broadcast table: ingress port P -> mcast_grp P
	for ingress := 1; ingress <= *ports; ingress++ {
		entry, err := tableentry.NewBuilder(p, "MyIngress.broadcast").
			Match("standard_metadata.ingress_port",
				tableentry.Exact(codec.MustEncodeUint(uint64(ingress), 9))).
			Action("MyIngress.set_mcast_grp",
				tableentry.Param("mcast_grp", codec.MustEncodeUint(uint64(ingress), 16))).
			Build()
		if err != nil {
			log.Fatalf("build broadcast entry: %v", err)
		}
		if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			log.Fatalf("insert broadcast entry: %v", err)
		}
	}
	log.Printf("installed %d broadcast table entries", *ports)

	// Subscribe to the digest stream.
	digestSub, err := digest.NewSubscriber(c, p)
	if err != nil {
		log.Fatalf("digest subscriber: %v", err)
	}

	// Track already-learned MACs so repeated digests for the same MAC
	// don't try to double-insert.
	var learnedMu sync.Mutex
	learned := map[string]uint32{}

	digestSub.OnDigest("learn_t", func(ctx context.Context, msg *p4v1.DigestList) {
		for _, member := range msg.GetData() {
			srcMAC, ingressPort, ok := decodeLearnStruct(member)
			if !ok {
				log.Printf("digest: could not decode learn_t payload: %v", member)
				continue
			}
			key := hex.EncodeToString(srcMAC)
			learnedMu.Lock()
			if existing, seen := learned[key]; seen && existing == ingressPort {
				learnedMu.Unlock()
				continue
			}
			learned[key] = ingressPort
			learnedMu.Unlock()
			installLearned(ctx, c, p, srcMAC, ingressPort)
		}
		if err := digestSub.Ack(ctx, msg); err != nil {
			log.Printf("digest ack: %v", err)
		}
	})
	fmt.Printf("learning-switch ready: %d ports, flooding unknown destinations\n", *ports)

	<-ctx.Done()
	log.Println("shutting down")
}

// decodeLearnStruct unpacks a digest payload carrying:
//   struct learn_t { macAddr_t srcAddr; port_t ingress_port; }
func decodeLearnStruct(d *p4v1.P4Data) (mac []byte, port uint32, ok bool) {
	sl := d.GetStruct()
	if sl == nil || len(sl.GetMembers()) < 2 {
		return nil, 0, false
	}
	macBytes := sl.GetMembers()[0].GetBitstring()
	portBytes := sl.GetMembers()[1].GetBitstring()
	if len(macBytes) == 0 || len(portBytes) == 0 {
		return nil, 0, false
	}
	mac = padLeft(macBytes, 6)
	port = uint32(decodeBig(portBytes))
	_ = binary.BigEndian
	return mac, port, true
}

func decodeBig(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = (v << 8) | uint64(x)
	}
	return v
}

func padLeft(b []byte, width int) []byte {
	if len(b) >= width {
		return b
	}
	out := make([]byte, width)
	copy(out[width-len(b):], b)
	return out
}

// installLearned writes the smac (suppresses future digests for this
// MAC) and dmac (forward target) entries for a newly-learned MAC.
func installLearned(ctx context.Context, c *client.Client, p *pipeline.Pipeline, mac []byte, port uint32) {
	log.Printf("learn: %s @ port %d", codec.FormatHex(mac), port)

	// smac: exact(srcAddr) -> NoAction. Stops BMv2 from re-firing the
	// digest for this MAC.
	smac, err := tableentry.NewBuilder(p, "MyIngress.smac").
		Match("hdr.ethernet.srcAddr", tableentry.Exact(mac)).
		Action("NoAction").
		Build()
	if err != nil {
		log.Printf("build smac: %v", err)
		return
	}
	if err := c.WriteTableEntry(ctx, client.UpdateInsert, smac); err != nil {
		log.Printf("insert smac %s: %v", codec.FormatHex(mac), err)
	}

	// dmac: exact(dstAddr) -> forward(port)
	dmac, err := tableentry.NewBuilder(p, "MyIngress.dmac").
		Match("hdr.ethernet.dstAddr", tableentry.Exact(mac)).
		Action("MyIngress.forward",
			tableentry.Param("egress_port", codec.MustEncodeUint(uint64(port), 9))).
		Build()
	if err != nil {
		log.Printf("build dmac: %v", err)
		return
	}
	if err := c.WriteTableEntry(ctx, client.UpdateInsert, dmac); err != nil {
		log.Printf("insert dmac %s: %v", codec.FormatHex(mac), err)
	}
}
