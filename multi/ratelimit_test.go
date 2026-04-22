package multi

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiterFreshAllowsAttempt(t *testing.T) {
	r := NewRateLimiter(5*time.Minute, 3)
	assert.True(t, r.Check("ip"), "fresh limiter must allow the first attempt")
}

func TestRateLimiterBlocksAfterMax(t *testing.T) {
	r := NewRateLimiter(5*time.Minute, 3)
	for i := 0; i < 3; i++ {
		assert.Truef(t, r.Check("ip"), "attempt %d unexpectedly blocked before reaching max", i)
		r.Record("ip")
	}
	assert.False(t, r.Check("ip"), "limiter must block after max failed attempts within the window")
}

func TestRateLimiterClearResets(t *testing.T) {
	r := NewRateLimiter(5*time.Minute, 2)
	r.Record("ip")
	r.Record("ip")
	assert.False(t, r.Check("ip"), "limiter must block after max attempts")

	r.Clear("ip")
	assert.True(t, r.Check("ip"), "Clear must reset the counter for the key")
}

func TestRateLimiterExpiredAttemptsDropped(t *testing.T) {
	r := NewRateLimiter(100*time.Millisecond, 2)
	// Inject two attempts that are already outside the window.
	old := time.Now().Add(-time.Hour)
	r.attempts["ip"] = []time.Time{old, old}

	assert.True(t, r.Check("ip"), "expired attempts must be pruned — Check should allow")

	// A key with only expired attempts must be deleted from the map to avoid unbounded growth.
	r.mu.Lock()
	_, stillPresent := r.attempts["ip"]
	r.mu.Unlock()
	assert.False(t, stillPresent, "key with only expired attempts must be deleted from the map")
}

func TestRateLimiterPartialWindow(t *testing.T) {
	r := NewRateLimiter(time.Minute, 3)
	now := time.Now()
	// Two outside the window, two inside.
	r.attempts["ip"] = []time.Time{
		now.Add(-2 * time.Minute),
		now.Add(-90 * time.Second),
		now.Add(-30 * time.Second),
		now.Add(-5 * time.Second),
	}

	assert.True(t, r.Check("ip"), "with 2 fresh attempts under max=3, Check must allow")

	r.mu.Lock()
	remaining := len(r.attempts["ip"])
	r.mu.Unlock()
	assert.Equal(t, 2, remaining, "only the two in-window entries should remain after prune")
}

func TestRateLimiterKeysAreIndependent(t *testing.T) {
	r := NewRateLimiter(5*time.Minute, 2)
	r.Record("ip-a")
	r.Record("ip-a")
	assert.False(t, r.Check("ip-a"), "ip-a must be blocked after reaching its max")
	assert.True(t, r.Check("ip-b"), "ip-b must not be affected by ip-a's attempts")
}

func TestRateLimiterConcurrentAccess(t *testing.T) {
	// Exercises Check/Record/Clear across goroutines; meaningful under -race.
	r := NewRateLimiter(time.Minute, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				r.Check("ip")
				r.Record("ip")
				if j%50 == 0 {
					r.Clear("ip")
				}
			}
		}()
	}
	wg.Wait()
}
