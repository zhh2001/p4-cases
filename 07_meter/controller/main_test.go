package main

import (
	"testing"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/meter"
)

func TestValidateConfig(t *testing.T) {
	valid := meter.Config{CIR: 10, CBurst: 5, PIR: 20, PBurst: 10}
	for _, cfg := range []meter.Config{valid, {CIR: 10, CBurst: 20, PIR: 10, PBurst: 5}} {
		if err := validateConfig(cfg); err != nil {
			t.Fatalf("positive rates and bursts: %v", err)
		}
	}
	for _, cfg := range []meter.Config{
		{CIR: 0, CBurst: 5, PIR: 20, PBurst: 10},
		{CIR: -1, CBurst: 5, PIR: 20, PBurst: 10},
		{CIR: 10, CBurst: 0, PIR: 20, PBurst: 10},
		{CIR: 10, CBurst: 5, PIR: -20, PBurst: 10},
		{CIR: 10, CBurst: 5, PIR: 20, PBurst: 0},
		{CIR: 20, CBurst: 5, PIR: 10, PBurst: 10},
	} {
		if err := validateConfig(cfg); err == nil {
			t.Fatalf("accepted unsupported configuration: %+v", cfg)
		}
	}
}

func TestCheckMeterConfig(t *testing.T) {
	expected := meter.Config{CIR: 10, CBurst: 5, PIR: 20, PBurst: 10}
	entry := func() *p4v1.MeterEntry {
		return &p4v1.MeterEntry{
			Index:  &p4v1.Index{Index: meterIndex},
			Config: &p4v1.MeterConfig{Cir: 10, Cburst: 5, Pir: 20, Pburst: 10},
		}
	}
	if err := checkMeterConfig([]*p4v1.MeterEntry{entry()}, expected); err != nil {
		t.Fatalf("matching configuration: %v", err)
	}
	for _, entries := range [][]*p4v1.MeterEntry{
		nil, {nil}, {entry(), entry()}, {{Config: entry().Config}},
		{{Index: &p4v1.Index{Index: 1}, Config: entry().Config}},
		{{Index: &p4v1.Index{Index: meterIndex}}},
	} {
		if err := checkMeterConfig(entries, expected); err == nil {
			t.Fatalf("accepted incomplete or unexpected readback: %v", entries)
		}
	}
	for _, field := range []string{"cir", "cburst", "pir", "pburst"} {
		e := entry()
		switch field {
		case "cir":
			e.Config.Cir++
		case "cburst":
			e.Config.Cburst++
		case "pir":
			e.Config.Pir++
		case "pburst":
			e.Config.Pburst++
		}
		if err := checkMeterConfig([]*p4v1.MeterEntry{e}, expected); err == nil {
			t.Fatalf("accepted changed %s", field)
		}
	}
}
