package main

import (
	"net"
	"testing"
)

func TestHostMACsUseNumericHexOctets(t *testing.T) {
	for number := 1; number <= 128; number++ {
		value := macOfHost(number)
		mac, err := net.ParseMAC(value)
		if err != nil || len(mac) != 6 || mac[5] != byte(number) {
			t.Fatalf("host %d has an invalid MAC: %s (%v)", number, value, err)
		}
	}
	if got := macOfHost(100); got != "00:00:00:00:00:64" {
		t.Fatalf("host 100 MAC: %s", got)
	}
}

func TestHostCountRespectsTableCapacity(t *testing.T) {
	for _, number := range []int{1, 4, 100, 128} {
		if err := validateHostCount(number); err != nil {
			t.Fatalf("valid host count %d rejected: %v", number, err)
		}
	}
	for _, number := range []int{-1, 0, 129, 254, 255, 512} {
		if err := validateHostCount(number); err == nil {
			t.Fatalf("invalid host count %d accepted", number)
		}
	}
}

func TestMulticastGroupsDeliverExactlyOnceToOtherPorts(t *testing.T) {
	if groups := multicastGroups(1); len(groups) != 0 {
		t.Fatalf("single-host topology has %d multicast groups", len(groups))
	}
	for _, hosts := range []int{2, 4, 12, 128} {
		groups := multicastGroups(hosts)
		if len(groups) != hosts {
			t.Fatalf("%d hosts have %d groups", hosts, len(groups))
		}
		for index, group := range groups {
			ingress := uint32(index + 1)
			if group.ID != ingress || len(group.Replicas) != hosts-1 {
				t.Fatalf("ingress %d has an invalid group: %+v", ingress, group)
			}
			seen := make(map[uint32]bool)
			for _, replica := range group.Replicas {
				port := replica.EgressPort
				if port == 0 || port > uint32(hosts) || port == ingress || replica.Instance != 0 || seen[port] {
					t.Fatalf("ingress %d has an invalid or repeated replica: %+v", ingress, replica)
				}
				seen[port] = true
			}
			for port := uint32(1); port <= uint32(hosts); port++ {
				if seen[port] != (port != ingress) {
					t.Fatalf("ingress %d has unexpected delivery to port %d", ingress, port)
				}
			}
		}
	}
}
