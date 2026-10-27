// Package verification deduplicates successful cryptographic checks within one
// node or independent verifier. Never share a cache between committee members.
package verification

import (
	"Tyche/utils/cryptoexec"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sync"
)

type Key [sha256.Size]byte
type result struct {
	done  chan struct{}
	valid bool
}
type Stats struct{ Executions, Hits, Entries uint64 }

// Cache retains successful results for its owner's lifetime. Invalid results
// are not retained. Concurrent identical checks join the same in-flight check.
// Keys must bind the verification domain, public parameters and COMPLETE input.
type Cache struct {
	mu               sync.Mutex
	results          map[Key]*result
	executions, hits uint64
}

func New() *Cache { return &Cache{results: make(map[Key]*result)} }

// Select supplies an isolated cache unless the owner explicitly passes its own.
func Select(caches ...*Cache) *Cache {
	if len(caches) > 0 && caches[0] != nil {
		return caches[0]
	}
	return New()
}

// Optional preserves the stateless behavior of standalone verification APIs.
func Optional(caches ...*Cache) *Cache {
	if len(caches) > 0 {
		return caches[0]
	}
	return nil
}

func Digest(domain string, parts ...[]byte) Key {
	h := sha256.New()
	for _, p := range append([][]byte{[]byte(domain)}, parts...) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var key Key
	copy(key[:], h.Sum(nil))
	return key
}

func JSONKey(domain string, values ...any) Key {
	raw, err := json.Marshal(values)
	if err != nil {
		panic(err)
	} // Internal typed protocol records only.
	return Digest(domain, raw)
}

// Check executes work at most once for an identical successful input. All
// callers, including waiters, get only a boolean, never a mutable cached object.
func (c *Cache) Check(key Key, work func() bool) (valid bool) {
	return c.checkBudget(key, work, false)
}

func (c *Cache) checkBudget(key Key, work func() bool, fast bool) (valid bool) {
	if c != nil {
		c.mu.Lock()
		old := c.results[key]
		if old != nil {
			c.hits++
			c.mu.Unlock()
			<-old.done
			return old.valid
		}
		c.mu.Unlock()
	}
	// Reserve a miss only after it is executing on a budget worker. Otherwise
	// a worker could wait for an owner that is still queued behind that worker.
	if fast {
		cryptoexec.WithCPUGroupFast(func() { valid = c.check(key, work) })
	} else {
		cryptoexec.WithCPUGroup(func() { valid = c.check(key, work) })
	}
	return valid
}

func (c *Cache) check(key Key, work func() bool) (valid bool) {
	if c == nil {
		return work()
	}
	c.mu.Lock()
	if c.results == nil {
		c.results = make(map[Key]*result)
	}
	if old := c.results[key]; old != nil {
		c.hits++
		c.mu.Unlock()
		<-old.done
		return old.valid
	}
	r := &result{done: make(chan struct{})}
	c.results[key] = r
	c.executions++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		r.valid = valid
		if !valid {
			delete(c.results, key)
		}
		close(r.done)
		c.mu.Unlock()
	}()
	valid = work()
	return valid
}

func (c *Cache) Ed25519(public ed25519.PublicKey, message, signature []byte) bool {
	valid, _ := c.Ed25519Once(public, message, signature)
	return valid
}

// Ed25519Once also reports whether this caller performed the actual Ed25519
// operation, so metrics do not count cache hits as cryptographic verifications.
func (c *Cache) Ed25519Once(public ed25519.PublicKey, message, signature []byte) (valid, executed bool) {
	if len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false, false
	}
	valid = c.checkBudget(Digest("ed25519", public, message, signature), func() bool {
		executed = true
		return ed25519.Verify(public, message, signature)
	}, true)
	return valid, executed
}

func (c *Cache) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{c.executions, c.hits, uint64(len(c.results))}
}
