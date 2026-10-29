// Package netutil holds the connection hygiene shared by all TCP sensors:
// connection limits and deadlines, so an attacker can't exhaust the host by
// opening thousands of sockets or holding them open forever.
package netutil

import (
	"net"
	"strconv"
	"sync"
	"time"
)

// Limiter caps concurrent connections globally and per source IP.
type Limiter struct {
	mu    sync.Mutex
	total int
	perIP map[string]int
	max   int
	maxIP int
}

func NewLimiter(max, maxPerIP int) *Limiter {
	return &Limiter{perIP: map[string]int{}, max: max, maxIP: maxPerIP}
}

// Acquire reserves a slot for ip; callers must Release it when done.
func (l *Limiter) Acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= l.max || l.perIP[ip] >= l.maxIP {
		return false
	}
	l.total++
	l.perIP[ip]++
	return true
}

func (l *Limiter) Release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
}

// DeadlineConn refreshes an idle deadline on every read and write, but never
// past a hard stop: bots that trickle one byte a minute still get cut off.
type DeadlineConn struct {
	net.Conn
	Idle     time.Duration
	HardStop time.Time
}

func (c *DeadlineConn) deadline() time.Time {
	d := time.Now().Add(c.Idle)
	if !c.HardStop.IsZero() && d.After(c.HardStop) {
		return c.HardStop
	}
	return d
}

func (c *DeadlineConn) Read(p []byte) (int, error) {
	c.Conn.SetReadDeadline(c.deadline())
	return c.Conn.Read(p)
}

func (c *DeadlineConn) Write(p []byte) (int, error) {
	c.Conn.SetWriteDeadline(c.deadline())
	return c.Conn.Write(p)
}

// SplitAddr returns the IP and port of a remote address.
func SplitAddr(a net.Addr) (string, int) {
	host, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String(), 0
	}
	p, _ := strconv.Atoi(port)
	return host, p
}
