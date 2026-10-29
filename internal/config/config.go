// Package config reads settings from HONEYNET_* environment variables,
// with command-line flags taking precedence.
package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	SSHAddr       string
	TelnetAddr    string
	HTTPAddr      string
	DashboardAddr string
	DataDir       string
	GeoIPDB       string
	Hostname      string
	Token         string
	Origins       []string
	LogLevel      string
	MaxConns      int
	MaxConnsPerIP int
	Retention     time.Duration
	Demo          bool
}

func env(key, def string) string {
	if v, ok := os.LookupEnv("HONEYNET_" + key); ok {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(env(key, "")); err == nil {
		return v
	}
	return def
}

// Load parses args (os.Args[1:]) on top of the environment.
func Load(args []string) (Config, error) {
	var c Config
	fs := flag.NewFlagSet("honeynet", flag.ContinueOnError)
	fs.StringVar(&c.SSHAddr, "ssh", env("SSH_ADDR", ":2222"), "SSH honeypot address (empty disables)")
	fs.StringVar(&c.TelnetAddr, "telnet", env("TELNET_ADDR", ":2323"), "Telnet honeypot address (empty disables)")
	fs.StringVar(&c.HTTPAddr, "http", env("HTTP_ADDR", ":8080"), "HTTP honeypot address (empty disables)")
	fs.StringVar(&c.DashboardAddr, "dashboard", env("DASHBOARD_ADDR", "127.0.0.1:9000"), "dashboard address; keep it private")
	fs.StringVar(&c.DataDir, "data", env("DATA_DIR", "./data"), "directory for the database and SSH host keys")
	fs.StringVar(&c.GeoIPDB, "geoip", env("GEOIP_DB", ""), "path to GeoLite2-City.mmdb (optional)")
	fs.StringVar(&c.Hostname, "hostname", env("HOSTNAME_FAKE", "srv-prod-01"), "hostname the fake shell reports")
	fs.StringVar(&c.Token, "token", env("DASHBOARD_TOKEN", ""), "bearer token required by the dashboard API")
	origins := fs.String("origins", env("DASHBOARD_ORIGINS", ""), "comma-separated extra WebSocket origins, e.g. localhost:5173")
	fs.StringVar(&c.LogLevel, "log-level", env("LOG_LEVEL", "info"), "debug, info, warn or error")
	fs.IntVar(&c.MaxConns, "max-conns", envInt("MAX_CONNS", 512), "max concurrent honeypot connections")
	fs.IntVar(&c.MaxConnsPerIP, "max-conns-per-ip", envInt("MAX_CONNS_PER_IP", 8), "max concurrent connections per source IP")
	retention := fs.String("retention", env("RETENTION", "30d"), "delete events older than this (e.g. 72h, 30d; 0 keeps everything)")
	demo, _ := strconv.ParseBool(env("DEMO", "false"))
	fs.BoolVar(&c.Demo, "demo", demo, "generate synthetic attack traffic for the dashboard")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	for _, o := range strings.Split(*origins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.Origins = append(c.Origins, o)
		}
	}
	var err error
	if c.Retention, err = parseDuration(*retention); err != nil {
		return c, fmt.Errorf("retention: %w", err)
	}
	if c.DashboardAddr == "" {
		return c, fmt.Errorf("dashboard address is required")
	}
	return c, nil
}

// parseDuration is time.ParseDuration plus a "d" (days) suffix.
func parseDuration(s string) (time.Duration, error) {
	if s == "" || s == "0" {
		return 0, nil
	}
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
