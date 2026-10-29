// Package event defines the single record type that every honeypot sensor
// produces, plus a small in-process pub/sub bus used for the live feed.
package event

import "time"

// Sensor identifies the honeypot that observed an event.
type Sensor string

const (
	SensorSSH    Sensor = "ssh"
	SensorTelnet Sensor = "telnet"
	SensorHTTP   Sensor = "http"
)

// Kind is what happened.
type Kind string

const (
	KindConnect    Kind = "connect"    // TCP connection accepted
	KindAuth       Kind = "auth"       // login attempt (password or public key)
	KindCommand    Kind = "command"    // shell command typed or sent via exec
	KindRequest    Kind = "request"    // HTTP request
	KindTunnel     Kind = "tunnel"     // SSH port-forwarding attempt (direct-tcpip)
	KindDisconnect Kind = "disconnect" // connection closed
)

// Geo is the location of the source IP. Zero value means "unknown".
type Geo struct {
	CountryCode string  `json:"country_code,omitempty"`
	Country     string  `json:"country,omitempty"`
	City        string  `json:"city,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
}

// Known reports whether the location was resolved.
func (g Geo) Known() bool { return g.CountryCode != "" }

// Event is one observation. Fields that don't apply to a kind stay empty.
// Everything except ID, Time and Geo is attacker-controlled input.
type Event struct {
	ID        int64     `json:"id,omitempty"`
	Time      time.Time `json:"time"`
	Sensor    Sensor    `json:"sensor"`
	Kind      Kind      `json:"kind"`
	SessionID string    `json:"session_id,omitempty"`
	SrcIP     string    `json:"src_ip"`
	SrcPort   int       `json:"src_port,omitempty"`
	Geo

	Client   string `json:"client,omitempty"` // SSH client version banner
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Success  bool   `json:"success,omitempty"`

	Command string `json:"command,omitempty"`
	Output  string `json:"output,omitempty"`

	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Body      string `json:"body,omitempty"`

	Tags   []string `json:"tags,omitempty"`
	Detail string   `json:"detail,omitempty"` // free-form: key fingerprint, tunnel target, ...
}

// Emitter accepts events from sensors. Implementations must not block for long:
// a slow emitter would let an attacker stall the honeypot.
type Emitter interface {
	Emit(Event)
}

// EmitterFunc adapts a function to Emitter.
type EmitterFunc func(Event)

func (f EmitterFunc) Emit(e Event) { f(e) }
