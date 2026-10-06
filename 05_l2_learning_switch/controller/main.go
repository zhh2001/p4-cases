// Case 05: L2 MAC learning switch controller (digest variant).
//
// Flow:
//
//  1. Push the pipeline.
//  2. Install multicast groups 1..N and broadcast table entries so
//     frames with unknown destinations flood to every port except
//     the ingress.
//  3. Enable and subscribe to the `learn_t` digest. Every time BMv2 sees a
//     source MAC it has not seen before, it fires a digest carrying
//     (srcAddr, ingress_port). The controller installs matching
//     smac (source seen) + dmac (where to forward) entries so the
//     next frame reuses them instead of re-triggering the digest
//     and/or flooding.
//  4. Process digest lists until SIGTERM.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"

	"github.com/zhh2001/p4runtime-go-controller/client"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/digest"
	sdkerrors "github.com/zhh2001/p4runtime-go-controller/errors"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/pre"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	if *ports < 2 || *ports > 254 {
		log.Fatal("-ports must be between 2 and 254")
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

	// Register the callback before enabling notifications on the switch.
	digestSub, err := digest.NewSubscriber(c, p)
	if err != nil {
		log.Fatalf("digest subscriber: %v", err)
	}

	pending := make(chan *p4v1.DigestList, 256)
	unsubscribe := digestSub.OnDigest("learn_t", func(_ context.Context, msg *p4v1.DigestList) {
		select {
		case pending <- msg:
		case <-ctx.Done():
		default:
			log.Printf("digest queue full, skipped list %d", msg.GetListId())
		}
	})
	defer unsubscribe()
	if err := enableDigest(ctx, c, p); err != nil {
		log.Fatalf("enable learn_t: %v", err)
	}
	learner := macLearner{writer: c, pipeline: p, ports: uint32(*ports), learned: map[string]uint32{}}
	fmt.Printf("learning-switch ready: %d ports, flooding unknown destinations\n", *ports)

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			return
		case msg := <-pending:
			learnCtx, learnCancel := context.WithTimeout(ctx, 2*time.Second)
			for _, member := range msg.GetData() {
				mac, port, ok := decodeLearnStruct(member)
				if !ok {
					log.Printf("digest: invalid learn_t payload: %v", member)
					continue
				}
				if err := learner.learn(learnCtx, mac, port); err != nil {
					log.Printf("learn %s: %v", codec.FormatHex(mac), err)
				}
			}
			if err := digestSub.Ack(learnCtx, msg); err != nil {
				log.Printf("digest ack: %v", err)
			}
			learnCancel()
		}
	}
}

type runtimeWriter interface {
	Write(context.Context, client.WriteOptions, ...*p4v1.Update) error
}

func enableDigest(ctx context.Context, c runtimeWriter, p *pipeline.Pipeline) error {
	definition, ok := p.Digest("learn_t")
	if !ok {
		return errors.New("learn_t is missing from P4Info")
	}
	return c.Write(ctx, client.WriteOptions{}, &p4v1.Update{
		Type: p4v1.Update_INSERT,
		Entity: &p4v1.Entity{Entity: &p4v1.Entity_DigestEntry{DigestEntry: &p4v1.DigestEntry{
			DigestId: definition.ID,
			Config: &p4v1.DigestEntry_Config{
				MaxTimeoutNs: 0,
				MaxListSize:  1,
				AckTimeoutNs: int64(time.Second),
			},
		}}},
	})
}

// decodeLearnStruct unpacks a digest payload carrying:
//
//	struct learn_t { macAddr_t srcAddr; port_t ingress_port; }
func decodeLearnStruct(d *p4v1.P4Data) (mac []byte, port uint32, ok bool) {
	sl := d.GetStruct()
	if sl == nil || len(sl.GetMembers()) != 2 {
		return nil, 0, false
	}
	macBytes := sl.GetMembers()[0].GetBitstring()
	portBytes := sl.GetMembers()[1].GetBitstring()
	if len(macBytes) == 0 || len(macBytes) > 6 || len(portBytes) == 0 || len(portBytes) > 2 {
		return nil, 0, false
	}
	mac = make([]byte, 6)
	copy(mac[6-len(macBytes):], macBytes)
	for _, value := range portBytes {
		port = (port << 8) | uint32(value)
	}
	return mac, port, port > 0 && port < 512
}

type tableWriter interface {
	WriteTableEntry(context.Context, client.UpdateType, *p4v1.TableEntry) error
}

type macLearner struct {
	writer   tableWriter
	pipeline *pipeline.Pipeline
	ports    uint32
	learned  map[string]uint32
}

func (l *macLearner) learn(ctx context.Context, mac []byte, port uint32) error {
	if len(mac) != 6 || mac[0]&1 != 0 || hex.EncodeToString(mac) == "000000000000" {
		return errors.New("source MAC must be a non-zero unicast address")
	}
	if port == 0 || port > l.ports {
		return fmt.Errorf("ingress port %d is outside the configured host ports", port)
	}
	key := hex.EncodeToString(mac)
	if existing, seen := l.learned[key]; seen {
		if existing != port {
			return fmt.Errorf("MAC is already bound to port %d, movement is not supported", existing)
		}
		return nil
	}
	if err := installLearned(ctx, l.writer, l.pipeline, mac, port); err != nil {
		return err
	}
	l.learned[key] = port
	log.Printf("learn: %s @ port %d", codec.FormatHex(mac), port)
	return nil
}

// Install forwarding before suppressing future digests for this MAC.
func installLearned(ctx context.Context, c tableWriter, p *pipeline.Pipeline, mac []byte, port uint32) error {
	smac, err := tableentry.NewBuilder(p, "MyIngress.smac").
		Match("hdr.ethernet.srcAddr", tableentry.Exact(mac)).
		Action("NoAction").
		Build()
	if err != nil {
		return fmt.Errorf("build smac: %w", err)
	}

	// dmac: exact(dstAddr) -> forward(port)
	dmac, err := tableentry.NewBuilder(p, "MyIngress.dmac").
		Match("hdr.ethernet.dstAddr", tableentry.Exact(mac)).
		Action("MyIngress.forward",
			tableentry.Param("egress_port", codec.MustEncodeUint(uint64(port), 9))).
		Build()
	if err != nil {
		return fmt.Errorf("build dmac: %w", err)
	}
	if err := upsertEntry(ctx, c, dmac); err != nil {
		return fmt.Errorf("write dmac: %w", err)
	}
	if err := upsertEntry(ctx, c, smac); err != nil {
		return fmt.Errorf("write smac: %w", err)
	}
	return nil
}

func upsertEntry(ctx context.Context, c tableWriter, entry *p4v1.TableEntry) error {
	err := c.WriteTableEntry(ctx, client.UpdateInsert, entry)
	if errors.Is(err, sdkerrors.ErrEntryExists) || status.Code(err) == codes.AlreadyExists {
		return c.WriteTableEntry(ctx, client.UpdateModify, entry)
	}
	// P4Runtime may report per-update errors inside an UNKNOWN batch status.
	st, ok := status.FromError(err)
	if ok && st.Code() == codes.Unknown {
		details := st.Details()
		if len(details) == 1 {
			if detail, ok := details[0].(*p4v1.Error); ok && detail.GetCanonicalCode() == int32(codes.AlreadyExists) {
				return c.WriteTableEntry(ctx, client.UpdateModify, entry)
			}
		}
	}
	return err
}
