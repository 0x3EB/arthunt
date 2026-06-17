package scan

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

// Limiter is a global, jittered request pacer shared by all workers. It enforces
// an average rate while randomising the exact spacing between calls so the
// access pattern looks organic rather than a clockwork burst.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration // base spacing between requests
	jitter   float64       // 0..1 fraction of interval applied as +/- jitter
	next     time.Time
	started  bool
}

// NewLimiter builds a limiter for ratePerSec requests/second. jitterFrac in
// [0,1] widens/narrows spacing randomly (e.g. 0.5 => +/-50%). rate<=0 disables.
func NewLimiter(ratePerSec, jitterFrac float64) *Limiter {
	if ratePerSec <= 0 {
		return &Limiter{interval: 0}
	}
	if jitterFrac < 0 {
		jitterFrac = 0
	}
	if jitterFrac > 1 {
		jitterFrac = 1
	}
	return &Limiter{
		interval: time.Duration(float64(time.Second) / ratePerSec),
		jitter:   jitterFrac,
	}
}

// SlowTo lowers the rate to at most ratePerSec — it only ever increases the
// spacing (slows down), never speeds up past the configured profile. Used to
// spread a scan over a requested wall-clock window for maximum stealth.
func (l *Limiter) SlowTo(ratePerSec float64) {
	if l == nil || ratePerSec <= 0 {
		return
	}
	want := time.Duration(float64(time.Second) / ratePerSec)
	l.mu.Lock()
	defer l.mu.Unlock()
	if want > l.interval {
		l.interval = want
	}
}

// Wait blocks until the next request is permitted, or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.interval == 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	if !l.started {
		l.started = true
		l.next = now
	}
	// Apply random jitter to this interval.
	d := l.interval
	if l.jitter > 0 {
		factor := 1 + (rand.Float64()*2-1)*l.jitter // in [1-j, 1+j]
		d = time.Duration(float64(d) * factor)
	}
	wakeAt := l.next
	if wakeAt.Before(now) {
		wakeAt = now
	}
	l.next = wakeAt.Add(d)
	sleep := time.Until(wakeAt)
	l.mu.Unlock()

	if sleep <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(sleep)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
