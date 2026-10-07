package main

import (
	"net"
	"testing"
)

func TestHostMACsUseValidHexOctetsAcrossTheSubnet(t *testing.T) {
	for number, want := range map[int]string{
		1: "00:00:00:00:00:01", 10: "00:00:00:00:00:0a",
		16: "00:00:00:00:00:10", 100: "00:00:00:00:00:64",
		254: "00:00:00:00:00:fe",
	} {
		if got := macOfHost(number); got != want {
			t.Fatalf("host %d MAC: got %s, want %s", number, got, want)
		}
	}
	seen := make(map[string]bool)
	for number := 1; number <= 254; number++ {
		value := macOfHost(number)
		mac, err := net.ParseMAC(value)
		if err != nil || len(mac) != 6 || mac[5] != byte(number) || seen[value] {
			t.Fatalf("host %d has an invalid or duplicate MAC: %s (%v)", number, value, err)
		}
		seen[value] = true
	}
}

func TestHostCountRespectsUsableIPv4Addresses(t *testing.T) {
	for _, number := range []int{1, 4, 100, 254} {
		if err := validateHostCount(number); err != nil {
			t.Fatalf("valid host count %d rejected: %v", number, err)
		}
	}
	for _, number := range []int{-1, 0, 255, 256, 511, 512} {
		if err := validateHostCount(number); err == nil {
			t.Fatalf("invalid host count %d accepted", number)
		}
	}
}
