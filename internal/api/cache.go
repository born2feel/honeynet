package api

import (
	"sync"
	"time"
)

// cache keeps aggregate responses for a few seconds. Every open dashboard tab
// polls /api/stats, and without this each poll would rescan the event table.
type cache struct {
	ttl time.Duration

	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	val     any
	expires time.Time
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, entries: map[string]cacheEntry{}}
}

func (c *cache) get(key string, load func() (any, error)) (any, error) {
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.val, nil
	}
	c.mu.Unlock()

	v, err := load()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > 256 { // keys come from query strings: bound them
		c.entries = map[string]cacheEntry{}
	}
	c.entries[key] = cacheEntry{val: v, expires: now.Add(c.ttl)}
	return v, nil
}
