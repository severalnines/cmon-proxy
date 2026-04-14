package multi

// This file is part of cmon-proxy.
//
// cmon-proxy is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2 of the License.
//
// cmon-proxy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with cmon-proxy. If not, see <https://www.gnu.org/licenses/>.

import (
	"sync"
	"time"
)

// RateLimiter is a thread-safe sliding-window rate limiter that tracks
// failed attempts per key and blocks further attempts once the limit is
// exceeded within the window.
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	window   time.Duration
	max      int
}

// NewRateLimiter creates a RateLimiter with the given window duration and
// maximum number of allowed failed attempts within that window.
func NewRateLimiter(window time.Duration, max int) *RateLimiter {
	return &RateLimiter{
		attempts: make(map[string][]time.Time),
		window:   window,
		max:      max,
	}
}

// Check returns true if the key is allowed to make another attempt.
// It prunes expired entries before checking the count.
func (r *RateLimiter) Check(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(key)
	return len(r.attempts[key]) < r.max
}

// Record records a failed attempt for the key.
func (r *RateLimiter) Record(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts[key] = append(r.attempts[key], time.Now())
}

// Clear removes all recorded attempts for the key (call on successful auth).
func (r *RateLimiter) Clear(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.attempts, key)
}

// prune removes attempts older than the window. Must be called with r.mu held.
func (r *RateLimiter) prune(key string) {
	cutoff := time.Now().Add(-r.window)
	prev := r.attempts[key]
	recent := prev[:0]
	for _, t := range prev {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(r.attempts, key)
	} else {
		r.attempts[key] = recent
	}
}

var (
	// loginLimiter guards the login endpoint, keyed by client IP.
	// Allows up to 10 failed attempts within a 5-minute window.
	loginLimiter = NewRateLimiter(5*time.Minute, 10)

	// elevationLimiter guards the elevation endpoint, keyed by session ID.
	// Allows up to 5 failed attempts within a 5-minute window.
	elevationLimiter = NewRateLimiter(5*time.Minute, 5)
)
