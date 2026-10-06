package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/client"
	sdkerrors "github.com/zhh2001/p4runtime-go-controller/errors"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testP4Info = `
tables {
 preamble { id: 33554433 name: "MyIngress.smac" }
 match_fields { id: 1 name: "hdr.ethernet.srcAddr" bitwidth: 48 match_type: EXACT }
 action_refs { id: 16777217 } size: 256
}
tables {
 preamble { id: 33554434 name: "MyIngress.dmac" }
 match_fields { id: 1 name: "hdr.ethernet.dstAddr" bitwidth: 48 match_type: EXACT }
 action_refs { id: 16777218 } size: 256
}
actions { preamble { id: 16777217 name: "NoAction" } }
actions {
 preamble { id: 16777218 name: "MyIngress.forward" }
 params { id: 1 name: "egress_port" bitwidth: 9 }
}
digests { preamble { id: 385875969 name: "learn_t" } }
`

func testPipeline(t *testing.T) *pipeline.Pipeline {
	t.Helper()
	p, err := pipeline.LoadText([]byte(testP4Info), nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type fakeWriter struct {
	updates []*p4v1.Update
	kinds   []client.UpdateType
	entries []*p4v1.TableEntry
	errors  []error
}

func (w *fakeWriter) Write(_ context.Context, _ client.WriteOptions, updates ...*p4v1.Update) error {
	w.updates = append(w.updates, updates...)
	return w.nextError()
}

func (w *fakeWriter) WriteTableEntry(_ context.Context, kind client.UpdateType, entry *p4v1.TableEntry) error {
	w.kinds = append(w.kinds, kind)
	w.entries = append(w.entries, entry)
	return w.nextError()
}

func (w *fakeWriter) nextError() error {
	if len(w.errors) == 0 {
		return nil
	}
	err := w.errors[0]
	w.errors = w.errors[1:]
	return err
}

func TestEnableDigest(t *testing.T) {
	w := &fakeWriter{}
	p := testPipeline(t)
	if err := enableDigest(context.Background(), w, p); err != nil {
		t.Fatal(err)
	}
	if len(w.updates) != 1 || w.updates[0].GetType() != p4v1.Update_INSERT {
		t.Fatal("digest was not enabled with INSERT")
	}
	entry := w.updates[0].GetEntity().GetDigestEntry()
	definition, _ := p.Digest("learn_t")
	if entry.GetDigestId() != definition.ID || entry.GetConfig().GetMaxListSize() != 1 || entry.GetConfig().GetMaxTimeoutNs() != 0 || entry.GetConfig().GetAckTimeoutNs() <= 0 {
		t.Fatalf("unexpected digest config: %v", entry)
	}
}

func TestEnableDigestReportsMissingDefinitionAndWriteFailure(t *testing.T) {
	p, err := pipeline.LoadText([]byte(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &fakeWriter{}
	if enableDigest(context.Background(), w, p) == nil || len(w.updates) != 0 {
		t.Fatal("missing digest definition was accepted")
	}
	failure := errors.New("write failed")
	w.errors = []error{failure}
	if !errors.Is(enableDigest(context.Background(), w, testPipeline(t)), failure) {
		t.Fatal("digest write failure was hidden")
	}
}

func learnData(mac, port []byte) *p4v1.P4Data {
	return &p4v1.P4Data{Data: &p4v1.P4Data_Struct{Struct: &p4v1.P4StructLike{Members: []*p4v1.P4Data{
		{Data: &p4v1.P4Data_Bitstring{Bitstring: mac}},
		{Data: &p4v1.P4Data_Bitstring{Bitstring: port}},
	}}}}
}

func TestDecodeLearnStruct(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mac, port []byte
		valid     bool
		value     uint32
	}{
		{"compressed", []byte{1}, []byte{2}, true, 2},
		{"full width", []byte{0, 0, 0, 0, 0, 1}, []byte{1, 255}, true, 511},
		{"empty MAC", nil, []byte{1}, false, 0},
		{"oversized MAC", make([]byte, 7), []byte{1}, false, 0},
		{"empty port", []byte{1}, nil, false, 0},
		{"zero port", []byte{1}, []byte{0}, false, 0},
		{"port exceeds width", []byte{1}, []byte{2, 0}, false, 0},
		{"port overflow", []byte{1}, []byte{1, 0, 0, 0, 0, 1}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mac, port, ok := decodeLearnStruct(learnData(tc.mac, tc.port))
			if ok != tc.valid {
				t.Fatalf("valid=%v, want %v", ok, tc.valid)
			}
			if ok && (len(mac) != 6 || mac[5] != 1 || port != tc.value) {
				t.Fatalf("mac=%x port=%d", mac, port)
			}
		})
	}
	if _, _, ok := decodeLearnStruct(nil); ok {
		t.Fatal("nil digest accepted")
	}
	data := learnData([]byte{1}, []byte{1})
	data.GetStruct().Members = append(data.GetStruct().Members, &p4v1.P4Data{})
	if _, _, ok := decodeLearnStruct(data); ok {
		t.Fatal("extra struct field accepted")
	}
}

func newLearner(t *testing.T, writer tableWriter) *macLearner {
	return &macLearner{writer: writer, pipeline: testPipeline(t), ports: 4, learned: map[string]uint32{}}
}

func TestLearningInstallsDestinationBeforeSourceAndDeduplicates(t *testing.T) {
	w := &fakeWriter{}
	l := newLearner(t, w)
	mac := []byte{0, 0, 0, 0, 0, 2}
	if err := l.learn(context.Background(), mac, 2); err != nil {
		t.Fatal(err)
	}
	if len(w.entries) != 2 || w.entries[0].GetTableId() != 33554434 || w.entries[1].GetTableId() != 33554433 {
		t.Fatal("learning suppressed before installing forwarding")
	}
	if !bytes.Equal(w.entries[0].GetMatch()[0].GetExact().GetValue(), []byte{2}) || !bytes.Equal(w.entries[0].GetAction().GetAction().GetParams()[0].GetValue(), []byte{2}) {
		t.Fatalf("unexpected forwarding entry: %v", w.entries[0])
	}
	if err := l.learn(context.Background(), mac, 2); err != nil {
		t.Fatal(err)
	}
	if len(w.entries) != 2 {
		t.Fatal("duplicate digest wrote tables again")
	}
}

func TestLearningRetriesAfterPartialWriteFailure(t *testing.T) {
	failure := errors.New("source table unavailable")
	w := &fakeWriter{errors: []error{nil, failure}}
	l := newLearner(t, w)
	mac := []byte{0, 0, 0, 0, 0, 2}
	if err := l.learn(context.Background(), mac, 2); !errors.Is(err, failure) {
		t.Fatalf("partial failure hidden: %v", err)
	}
	if len(l.learned) != 0 {
		t.Fatal("incomplete learning was cached")
	}
	w.errors = []error{sdkerrors.ErrEntryExists, nil, nil}
	if err := l.learn(context.Background(), mac, 2); err != nil {
		t.Fatal(err)
	}
	if len(l.learned) != 1 || w.kinds[3] != client.UpdateModify {
		t.Fatal("partial forwarding entry was not reconciled")
	}
}

func TestDestinationWriteFailureDoesNotSuppressLearning(t *testing.T) {
	w := &fakeWriter{errors: []error{errors.New("destination table unavailable")}}
	l := newLearner(t, w)
	if l.learn(context.Background(), []byte{0, 0, 0, 0, 0, 1}, 1) == nil {
		t.Fatal("write failure hidden")
	}
	if len(w.entries) != 1 || len(l.learned) != 0 {
		t.Fatal("source was suppressed after forwarding failed")
	}
}

func TestLearningRejectsInvalidSourcesAndPorts(t *testing.T) {
	for _, tc := range []struct {
		mac  []byte
		port uint32
	}{
		{nil, 1}, {make([]byte, 6), 1}, {[]byte{1, 0, 0, 0, 0, 1}, 1},
		{[]byte{0, 0, 0, 0, 0, 1}, 0}, {[]byte{0, 0, 0, 0, 0, 1}, 5},
	} {
		w := &fakeWriter{}
		if newLearner(t, w).learn(context.Background(), tc.mac, tc.port) == nil || len(w.entries) != 0 {
			t.Fatalf("invalid source accepted: %v", tc)
		}
	}
}

func TestUpsertHandlesP4RuntimeBatchStatus(t *testing.T) {
	for _, code := range []codes.Code{codes.AlreadyExists, codes.PermissionDenied} {
		t.Run(code.String(), func(t *testing.T) {
			st, err := status.New(codes.Unknown, "batch error").WithDetails(&p4v1.Error{CanonicalCode: int32(code)})
			if err != nil {
				t.Fatal(err)
			}
			w := &fakeWriter{errors: []error{fmt.Errorf("write: %w", st.Err())}}
			err = upsertEntry(context.Background(), w, &p4v1.TableEntry{})
			if code == codes.AlreadyExists {
				if err != nil || len(w.kinds) != 2 || w.kinds[1] != client.UpdateModify {
					t.Fatal("existing entry was not updated")
				}
			} else if err == nil || len(w.kinds) != 1 {
				t.Fatal("unrelated write error was converted to MODIFY")
			}
		})
	}
}
