package main

import (
	"encoding/binary"
	"testing"
)

func cpuFrame(port uint16) []byte {
	frame := make([]byte, 64)
	binary.BigEndian.PutUint16(frame[12:14], expectedEthType)
	binary.BigEndian.PutUint16(frame[14:16], port)
	return frame
}

func TestDecodePacketIn(t *testing.T) {
	for _, port := range []uint16{1, 2} {
		payload := cpuFrame(port)
		got, err := decodePacketIn(payload)
		if err != nil || got != port {
			t.Fatalf("port=%d got=%d err=%v", port, got, err)
		}
		if got, err := decodePacketIn(payload[:16]); err != nil || got != port {
			t.Fatalf("header-only payload: port=%d got=%d err=%v", port, got, err)
		}
	}
}

func TestDecodePacketInRejectsTruncatedFrames(t *testing.T) {
	for length := 0; length < 16; length++ {
		if _, err := decodePacketIn(cpuFrame(1)[:length]); err == nil {
			t.Fatalf("accepted %d-byte payload", length)
		}
	}
}

func TestDecodePacketInRejectsOtherEtherTypes(t *testing.T) {
	for _, etherType := range []uint16{0, 0x0800, 0x88b5, 0xffff} {
		payload := cpuFrame(1)
		binary.BigEndian.PutUint16(payload[12:14], etherType)
		if _, err := decodePacketIn(payload); err == nil {
			t.Fatalf("accepted EtherType %04x", etherType)
		}
	}
}

func TestDecodePacketInRejectsPortsOutsideTopology(t *testing.T) {
	for _, port := range []uint16{0, 3, 256, 510, 511, 65535} {
		if _, err := decodePacketIn(cpuFrame(port)); err == nil {
			t.Fatalf("accepted ingress port %d", port)
		}
	}
}
