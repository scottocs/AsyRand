package tyche

import (
	"path/filepath"
	"testing"
)

func TestFileStateStorePersistsDoubleSignReservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node-state.json")
	store, err := NewFileStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveStateVote("parent", "child-a"); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.ReserveStateVote("parent", "child-b"); err == nil {
		t.Fatal("restarted store accepted a conflicting child for the same parent")
	}
	if err := reopened.ReserveStateVote("parent", "child-a"); err != nil {
		t.Fatalf("idempotent reservation failed: %v", err)
	}
	state, present, err := reopened.Load()
	if err != nil || !present {
		t.Fatalf("load: present=%v err=%v", present, err)
	}
	if state.SignedParents["parent"] != "child-a" {
		t.Fatalf("lost vote reservation: %+v", state.SignedParents)
	}
}

func TestMemoryStateStoreSaveCannotOverwriteVoteReservation(t *testing.T) {
	store := NewMemoryStateStore()
	if err := store.ReserveStateVote("parent", "child-a"); err != nil {
		t.Fatal(err)
	}
	stale := PersistentState{SignedParents: map[string]string{"parent": "child-b"}}
	if err := store.Save(stale); err == nil {
		t.Fatal("stale snapshot overwrote a safety reservation")
	}
}
