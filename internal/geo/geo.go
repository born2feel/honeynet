// Package geo resolves source IPs to a location using a MaxMind GeoLite2
// City database. Without a database every lookup returns "unknown", so the
// honeypot works out of the box and the map simply stays empty.
package geo

import (
	"net"
	"sync"

	"github.com/born2feel/honeynet/internal/event"
	"github.com/oschwald/geoip2-golang"
)

type Locator interface {
	Lookup(ip string) event.Geo
	Close() error
}

// Noop never resolves anything.
type Noop struct{}

func (Noop) Lookup(string) event.Geo { return event.Geo{} }
func (Noop) Close() error            { return nil }

// MaxMind reads a GeoLite2-City (or GeoIP2-City) .mmdb file.
type MaxMind struct {
	db *geoip2.Reader
}

func OpenMaxMind(path string) (*MaxMind, error) {
	db, err := geoip2.Open(path)
	if err != nil {
		return nil, err
	}
	return &MaxMind{db: db}, nil
}

func (m *MaxMind) Lookup(s string) event.Geo {
	ip := net.ParseIP(s)
	if ip == nil || !IsPublic(ip) {
		return event.Geo{}
	}
	rec, err := m.db.City(ip)
	if err != nil || rec.Country.IsoCode == "" {
		return event.Geo{}
	}
	return event.Geo{
		CountryCode: rec.Country.IsoCode,
		Country:     rec.Country.Names["en"],
		City:        rec.City.Names["en"],
		Lat:         rec.Location.Latitude,
		Lon:         rec.Location.Longitude,
	}
}

func (m *MaxMind) Close() error { return m.db.Close() }

// IsPublic reports whether ip is routable on the internet.
func IsPublic(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast())
}

// Cached wraps a Locator with a bounded cache: a brute-force bot hits us
// thousands of times from the same address.
type Cached struct {
	next Locator
	max  int

	mu    sync.Mutex
	cache map[string]event.Geo
}

func NewCached(next Locator, max int) *Cached {
	return &Cached{next: next, max: max, cache: make(map[string]event.Geo)}
}

func (c *Cached) Lookup(ip string) event.Geo {
	c.mu.Lock()
	g, ok := c.cache[ip]
	c.mu.Unlock()
	if ok {
		return g
	}
	g = c.next.Lookup(ip)
	c.mu.Lock()
	if len(c.cache) >= c.max {
		// Crude but sufficient eviction: start over. Lookups are cheap mmap reads.
		c.cache = make(map[string]event.Geo)
	}
	c.cache[ip] = g
	c.mu.Unlock()
	return g
}

func (c *Cached) Close() error { return c.next.Close() }
