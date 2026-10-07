// Case 08: per-port packet counter reader.
//
// Supports an indirect counter indexed by ingress port and a direct
// counter attached to one forwarding entry per ingress port.
package main

import (
	"bufio"
	"context"
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
	"github.com/zhh2001/p4runtime-go-controller/counter"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
)

type sample struct {
	packets int64
	bytes   int64
}

func indirectSample(entries []*counter.Data, port int64) (sample, error) {
	if len(entries) != 1 || entries[0] == nil || entries[0].Index != port {
		return sample{}, fmt.Errorf("expected one counter entry for port %d", port)
	}
	entry := entries[0]
	if entry.Packets < 0 || entry.Bytes < 0 {
		return sample{}, fmt.Errorf("negative counter values for port %d", port)
	}
	return sample{entry.Packets, entry.Bytes}, nil
}

func directSample(entities []*p4v1.Entity, key *p4v1.TableEntry) (sample, error) {
	if len(entities) != 1 || key == nil || len(key.Match) != 1 || key.Match[0].GetExact() == nil {
		return sample{}, fmt.Errorf("expected one direct counter entry")
	}
	entry := entities[0].GetDirectCounterEntry()
	table := entry.GetTableEntry()
	if entry == nil || entry.Data == nil || table == nil || table.TableId != key.TableId ||
		table.IsDefaultAction || len(table.Match) != 1 || table.Match[0].GetFieldId() != key.Match[0].GetFieldId() ||
		table.Match[0].GetExact() == nil {
		return sample{}, fmt.Errorf("direct counter reply does not match the requested table entry")
	}
	want, err := codec.DecodeUint(key.Match[0].GetExact().GetValue())
	if err != nil {
		return sample{}, err
	}
	actual, err := codec.DecodeUint(table.Match[0].GetExact().GetValue())
	if err != nil || actual != want || entry.Data.PacketCount < 0 || entry.Data.ByteCount < 0 {
		return sample{}, fmt.Errorf("invalid direct counter reply")
	}
	return sample{entry.Data.PacketCount, entry.Data.ByteCount}, nil
}

func prepareCounters(ctx context.Context, c *client.Client, p *pipeline.Pipeline) (
	func(context.Context, int64) (sample, error), string, error,
) {
	if _, ok := p.Counter("MyIngress.port_counter"); ok {
		r, err := counter.NewReader(c, p)
		if err != nil {
			return nil, "", err
		}
		return func(ctx context.Context, port int64) (sample, error) {
			entries, err := r.Read(ctx, "MyIngress.port_counter", port)
			if err != nil {
				return sample{}, err
			}
			return indirectSample(entries, port)
		}, "indirect", nil
	}
	definition, ok := p.DirectCounter("MyIngress.direct_port_counter")
	if !ok || definition.DirectTableName != "MyIngress.count_table" {
		return nil, "", fmt.Errorf("pipeline does not contain a supported port counter")
	}
	keys := make(map[int64]*p4v1.TableEntry)
	for _, port := range []int64{1, 2} {
		entry, err := tableentry.NewBuilder(p, definition.DirectTableName).
			Match("standard_metadata.ingress_port", tableentry.Exact(codec.MustEncodeUint(uint64(port), 9))).
			Action("MyIngress.forward", tableentry.Param("port", codec.MustEncodeUint(uint64(3-port), 9))).
			Build()
		if err != nil {
			return nil, "", err
		}
		writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err = c.WriteTableEntry(writeCtx, client.UpdateInsert, entry)
		cancel()
		if err != nil {
			return nil, "", err
		}
		keys[port] = &p4v1.TableEntry{TableId: entry.TableId, Match: entry.Match}
	}
	return func(ctx context.Context, port int64) (sample, error) {
		key, ok := keys[port]
		if !ok {
			return sample{}, fmt.Errorf("unsupported ingress port %d", port)
		}
		entities, err := c.Read(ctx, &p4v1.Entity{Entity: &p4v1.Entity_DirectCounterEntry{
			DirectCounterEntry: &p4v1.DirectCounterEntry{TableEntry: key},
		}})
		if err != nil {
			return sample{}, err
		}
		return directSample(entities, key)
	}, "direct", nil
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

	readCounter, variant, err := prepareCounters(ctx, c, p)
	if err != nil {
		log.Fatalf("prepare counters: %v", err)
	}
	fmt.Printf("counter ready: %s, send 'dump' to read ports 1 and 2\n", variant)

	scanner := bufio.NewScanner(os.Stdin)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if !scanner.Scan() {
			return
		}
		switch scanner.Text() {
		case "dump":
			for _, port := range []int64{1, 2} {
				readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
				value, err := readCounter(readCtx, port)
				readCancel()
				if err != nil {
					log.Fatalf("read counter for port %d: %v", port, err)
				}
				fmt.Printf("port=%d packets=%d bytes=%d\n", port, value.packets, value.bytes)
			}
			fmt.Println("dump-done")
		case "quit", "":
			return
		default:
			fmt.Printf("unknown command %q\n", scanner.Text())
		}
	}
}
