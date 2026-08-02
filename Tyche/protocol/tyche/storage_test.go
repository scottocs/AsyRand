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
	if err := store.ReserveBeaconVote("parent", "vote-a"); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.ReserveBeaconVote("parent", "vote-b"); err == nil {
		t.Fatal("restarted store accepted a conflicting child for the same parent")
	}
	if err := reopened.ReserveBeaconVote("parent", "vote-a"); err != nil {
		t.Fatalf("idempotent reservation failed: %v", err)
	}
	state, present, err := reopened.Load()
	if err != nil || !present {
		t.Fatalf("load: present=%v err=%v", present, err)
	}
	if state.SignedBeaconSlots["parent"] != "vote-a" {
		t.Fatalf("lost vote reservation: %+v", state.SignedBeaconSlots)
	}
}

func TestMemoryStateStoreSaveCannotOverwriteVoteReservation(t *testing.T) {
	store := NewMemoryStateStore()
	if err := store.ReserveBeaconVote("parent", "vote-a"); err != nil {
		t.Fatal(err)
	}
	stale := PersistentState{SignedBeaconSlots: map[string]string{"parent": "vote-b"}}
	if err := store.Save(stale); err == nil {
		t.Fatal("stale snapshot overwrote a safety reservation")
	}
}
