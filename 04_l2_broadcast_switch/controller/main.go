// Case 04: L2 broadcast switch controller.
//
// Unicast traffic is delivered via the dmac exact table (as in case 03).
// Traffic whose destination MAC is unknown hits select_mcast_grp which
// picks a multicast group sized to flood the packet out of every port
// except its ingress. Multicast groups themselves are installed through
// the Packet Replication Engine wrapper in the pre package.
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
	"github.com/zhh2001/p4runtime-go-controller/pre"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
)

func macOfHost(n int) string {
	return fmt.Sprintf("00:00:00:00:00:%02d", n)
}

func main() {
	var (
		addr   = flag.String("addr", "127.0.0.1:9559", "P4Runtime target address")
		p4info = flag.String("p4info", "", "path to p4info text proto (required)")
		config = flag.String("config", "", "path to BMv2 device config JSON (required)")
		dev    = flag.Uint64("device-id", 1, "device id")
		hosts  = flag.Int("hosts", 4, "number of hosts (= number of switch ports)")
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

	// 1) Unicast dmac entries — same as case 03.
	for n := 1; n <= *hosts; n++ {
		mac := macOfHost(n)
		entry, err := tableentry.NewBuilder(p, "MyIngress.dmac").
			Match("hdr.ethernet.dstAddr", tableentry.Exact(codec.MustMAC(mac))).
			Action("MyIngress.forward",
				tableentry.Param("egress_port", codec.MustEncodeUint(uint64(n), 9))).
			Build()
		if err != nil {
			log.Fatalf("build dmac entry: %v", err)
		}
		if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			log.Fatalf("insert dmac: %v", err)
		}
		log.Printf("dmac %s -> port %d", mac, n)
	}

	// 2) Multicast groups. For each ingress port P, create group P that
	//    replicates to every port EXCEPT P. Group IDs == ingress port
	//    for simplicity.
	preW, err := pre.NewWriter(c)
	if err != nil {
		log.Fatalf("pre writer: %v", err)
	}
	for ingress := 1; ingress <= *hosts; ingress++ {
		replicas := make([]pre.Replica, 0, *hosts-1)
		for p := 1; p <= *hosts; p++ {
			if p == ingress {
				continue
			}
			replicas = append(replicas, pre.Replica{EgressPort: uint32(p), Instance: 0})
		}
		if err := preW.InsertMulticastGroup(ctx, pre.MulticastGroup{
			ID:       uint32(ingress),
			Replicas: replicas,
		}); err != nil {
			log.Fatalf("insert multicast group %d: %v", ingress, err)
		}
		log.Printf("multicast group %d = ports %v", ingress, replicaPorts(replicas))
	}

	// 3) select_mcast_grp entries — ingress port -> multicast group.
	for ingress := 1; ingress <= *hosts; ingress++ {
		entry, err := tableentry.NewBuilder(p, "MyIngress.select_mcast_grp").
			Match("standard_metadata.ingress_port",
				tableentry.Exact(codec.MustEncodeUint(uint64(ingress), 9))).
			Action("MyIngress.set_mcast_grp",
				tableentry.Param("mcast_grp", codec.MustEncodeUint(uint64(ingress), 16))).
			Build()
		if err != nil {
			log.Fatalf("build select_mcast_grp entry: %v", err)
		}
		if err := c.WriteTableEntry(ctx, client.UpdateInsert, entry); err != nil {
			log.Fatalf("insert select_mcast_grp: %v", err)
		}
		log.Printf("ingress_port %d -> mcast_grp %d", ingress, ingress)
	}

	fmt.Printf("broadcast-switch ready: %d dmac entries, %d multicast groups\n",
		*hosts, *hosts)
	<-ctx.Done()
	log.Println("shutting down")
}

func replicaPorts(rs []pre.Replica) []uint32 {
	out := make([]uint32, len(rs))
	for i, r := range rs {
		out[i] = r.EgressPort
	}
	return out
}
