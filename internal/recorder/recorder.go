// Package recorder is the pipeline between sensors and storage:
// sensor → Emit → enrich (geo) → batch insert → publish to live subscribers.
package recorder

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/geo"
	"github.com/born2feel/honeynet/internal/store"
)

const (
	batchSize     = 256
	flushInterval = 250 * time.Millisecond
)

type Recorder struct {
	in      chan event.Event
	store   *store.Store
	geo     geo.Locator
	bus     *event.Bus
	log     *slog.Logger
	dropped atomic.Uint64
}

func New(st *store.Store, loc geo.Locator, bus *event.Bus, log *slog.Logger) *Recorder {
	return &Recorder{
		in:    make(chan event.Event, 8192),
		store: st,
		geo:   loc,
		bus:   bus,
		log:   log,
	}
}

// Emit queues an event without ever blocking the sensor. When the queue is
// full (a flood the disk can't keep up with) the event is dropped and counted.
func (r *Recorder) Emit(e event.Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	select {
	case r.in <- e:
	default:
		if n := r.dropped.Add(1); n%1000 == 1 {
			r.log.Warn("event queue full, dropping events", "dropped_total", n)
		}
	}
}

// Submit queues an event and waits for room. Used by the demo generator,
// which must not lose its backfill.
func (r *Recorder) Submit(ctx context.Context, e event.Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	select {
	case r.in <- e:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Dropped returns how many events were lost to back-pressure.
func (r *Recorder) Dropped() uint64 { return r.dropped.Load() }

// Run consumes the queue until ctx is cancelled, then flushes what's left.
func (r *Recorder) Run(ctx context.Context) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	batch := make([]event.Event, 0, batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Use a fresh context so the final flush on shutdown still lands.
		wctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		saved, err := r.store.InsertBatch(wctx, batch)
		cancel()
		if err != nil {
			r.log.Error("store events", "err", err, "count", len(batch))
		}
		for _, e := range saved {
			r.bus.Publish(e)
		}
		batch = batch[:0]
	}

	for {
		select {
		case e := <-r.in:
			batch = append(batch, r.enrich(e))
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			for {
				select {
				case e := <-r.in:
					batch = append(batch, r.enrich(e))
				default:
					flush()
					return
				}
			}
		}
	}
}

func (r *Recorder) enrich(e event.Event) event.Event {
	if !e.Geo.Known() {
		e.Geo = r.geo.Lookup(e.SrcIP)
	}
	return e
}
