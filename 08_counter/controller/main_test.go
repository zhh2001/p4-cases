package main

import (
	"testing"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/counter"
)

func TestIndirectSampleRequiresOneMatchingNonnegativeEntry(t *testing.T) {
	valid := &counter.Data{Index: 1, Packets: 30, Bytes: 18890}
	if value, err := indirectSample([]*counter.Data{valid}, 1); err != nil || value != (sample{30, 18890}) {
		t.Fatalf("matching sample: value=%+v err=%v", value, err)
	}
	for _, entries := range [][]*counter.Data{
		nil, {nil}, {valid, valid}, {{Index: 2, Packets: 30, Bytes: 18890}},
		{{Index: 1, Packets: -1}}, {{Index: 1, Bytes: -1}},
	} {
		if _, err := indirectSample(entries, 1); err == nil {
			t.Fatalf("accepted incomplete or unexpected reply: %v", entries)
		}
	}
}

func counterKey(value []byte) *p4v1.TableEntry {
	return &p4v1.TableEntry{
		TableId: 123,
		Match: []*p4v1.FieldMatch{{
			FieldId: 1,
			FieldMatchType: &p4v1.FieldMatch_Exact_{
				Exact: &p4v1.FieldMatch_Exact{Value: value},
			},
		}},
	}
}

func directReply() *p4v1.DirectCounterEntry {
	return &p4v1.DirectCounterEntry{
		TableEntry: counterKey([]byte{1}),
		Data:       &p4v1.CounterData{PacketCount: 30, ByteCount: 18890},
	}
}

func TestDirectSampleChecksTheTableEntryAndCounterData(t *testing.T) {
	key := counterKey([]byte{1})
	entity := func(entry *p4v1.DirectCounterEntry) *p4v1.Entity {
		return &p4v1.Entity{Entity: &p4v1.Entity_DirectCounterEntry{DirectCounterEntry: entry}}
	}
	for _, bytes := range [][]byte{{1}, {0, 1}} {
		entry := directReply()
		entry.TableEntry = counterKey(bytes)
		if value, err := directSample([]*p4v1.Entity{entity(entry)}, key); err != nil || value != (sample{30, 18890}) {
			t.Fatalf("matching sample: value=%+v err=%v", value, err)
		}
	}
	for _, replies := range [][]*p4v1.Entity{nil, {nil}, {{}}, {entity(directReply()), entity(directReply())}} {
		if _, err := directSample(replies, key); err == nil {
			t.Fatalf("accepted incomplete reply: %v", replies)
		}
	}
	mutations := []func(*p4v1.DirectCounterEntry){
		func(entry *p4v1.DirectCounterEntry) { entry.Data = nil },
		func(entry *p4v1.DirectCounterEntry) { entry.TableEntry = nil },
		func(entry *p4v1.DirectCounterEntry) { entry.TableEntry.TableId++ },
		func(entry *p4v1.DirectCounterEntry) { entry.TableEntry.IsDefaultAction = true },
		func(entry *p4v1.DirectCounterEntry) { entry.TableEntry.Match = nil },
		func(entry *p4v1.DirectCounterEntry) { entry.TableEntry.Match[0] = nil },
		func(entry *p4v1.DirectCounterEntry) { entry.TableEntry.Match[0].FieldId++ },
		func(entry *p4v1.DirectCounterEntry) { entry.TableEntry.Match[0].FieldMatchType = nil },
		func(entry *p4v1.DirectCounterEntry) { entry.TableEntry.Match[0].GetExact().Value = []byte{2} },
		func(entry *p4v1.DirectCounterEntry) { entry.Data.PacketCount = -1 },
		func(entry *p4v1.DirectCounterEntry) { entry.Data.ByteCount = -1 },
	}
	for index, mutate := range mutations {
		entry := directReply()
		mutate(entry)
		if _, err := directSample([]*p4v1.Entity{entity(entry)}, key); err == nil {
			t.Fatalf("accepted mutation %d", index)
		}
	}
}
