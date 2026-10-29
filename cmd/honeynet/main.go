// Command honeynet runs the SSH, Telnet and HTTP honeypots and the dashboard.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/born2feel/honeynet/internal/api"
	"github.com/born2feel/honeynet/internal/config"
	"github.com/born2feel/honeynet/internal/demo"
	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/geo"
	"github.com/born2feel/honeynet/internal/honeypot/httppot"
	"github.com/born2feel/honeynet/internal/honeypot/sshpot"
	"github.com/born2feel/honeynet/internal/honeypot/telnetpot"
	"github.com/born2feel/honeynet/internal/netutil"
	"github.com/born2feel/honeynet/internal/recorder"
	"github.com/born2feel/honeynet/internal/store"
	"github.com/born2feel/honeynet/web"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "honeynet:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Args[1:])
	if err != nil {
		return err
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	log.Info("starting honeynet", "version", version, "demo", cfg.Demo)

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "honeynet.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	var loc geo.Locator = geo.Noop{}
	if cfg.GeoIPDB != "" {
		mm, err := geo.OpenMaxMind(cfg.GeoIPDB)
		if err != nil {
			return fmt.Errorf("geoip: %w", err)
		}
		loc = mm
	} else {
		log.Warn("no GeoIP database configured, the attack map will stay empty (set HONEYNET_GEOIP_DB)")
	}
	loc = geo.NewCached(loc, 50_000)
	defer loc.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bus := event.NewBus()
	rec := recorder.New(st, loc, bus, log)
	recDone := make(chan struct{})
	recCtx, stopRec := context.WithCancel(context.Background())
	defer stopRec()
	go func() {
		rec.Run(recCtx)
		close(recDone)
	}()

	lim := netutil.NewLimiter(cfg.MaxConns, cfg.MaxConnsPerIP)
	var (
		wg      sync.WaitGroup
		sensors []string
		errs    = make(chan error, 4)
	)
	start := func(name string, fn func(context.Context) error) {
		sensors = append(sensors, name)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil {
				errs <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}

	if cfg.SSHAddr != "" {
		srv, err := sshpot.New(sshpot.Config{Addr: cfg.SSHAddr, HostKeyDir: filepath.Join(cfg.DataDir, "keys"), Hostname: cfg.Hostname},
			rec, lim, log.With("sensor", "ssh"))
		if err != nil {
			return err
		}
		start("ssh", srv.ListenAndServe)
	}
	if cfg.TelnetAddr != "" {
		start("telnet", telnetpot.New(telnetpot.Config{Addr: cfg.TelnetAddr, Hostname: cfg.Hostname}, rec, lim, log.With("sensor", "telnet")).ListenAndServe)
	}
	if cfg.HTTPAddr != "" {
		start("http", httppot.New(httppot.Config{Addr: cfg.HTTPAddr, Hostname: cfg.Hostname}, rec, log.With("sensor", "http")).ListenAndServe)
	}

	if cfg.Demo {
		go runDemo(ctx, cfg, rec, st, log)
	}
	if cfg.Retention > 0 {
		go prune(ctx, st, cfg.Retention, log)
	}

	dash := &http.Server{
		Addr: cfg.DashboardAddr,
		Handler: api.New(api.Config{Token: cfg.Token, OriginPatterns: cfg.Origins, Sensors: sensors, Hostname: cfg.Hostname, Demo: cfg.Demo},
			st, bus, web.Dist(), log.With("component", "api")).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if host, _, _ := net.SplitHostPort(cfg.DashboardAddr); host == "" || host == "0.0.0.0" || host == "::" {
		if cfg.Token == "" {
			log.Warn("dashboard is listening on all interfaces without a token; set HONEYNET_DASHBOARD_TOKEN")
		}
	}
	go func() {
		log.Info("dashboard listening", "addr", cfg.DashboardAddr)
		if err := dash.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("dashboard: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err = <-errs:
		log.Error("fatal", "err", err)
		stop()
	}

	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dash.Shutdown(sctx)
	wg.Wait()
	stopRec()
	<-recDone
	if d := rec.Dropped(); d > 0 {
		log.Warn("events dropped under load", "count", d)
	}
	return err
}

func runDemo(ctx context.Context, cfg config.Config, rec *recorder.Recorder, st *store.Store, log *slog.Logger) {
	gen := demo.New(cfg.Hostname, uint64(time.Now().UnixNano()))
	// Backfill only an empty database, so restarts don't pile up history.
	if evs, err := st.Recent(ctx, 1, 0); err == nil && len(evs) == 0 {
		// The last day matches the live rate (one session every ~6s) so the
		// timeline has no cliff; the rest of the week is sparser.
		log.Info("demo: backfilling 7 days of synthetic traffic")
		if err := gen.Backfill(ctx, rec.Submit, 24*time.Hour, 14_000); err != nil {
			return
		}
		if err := gen.Backfill(ctx, rec.Submit, 7*24*time.Hour, 8_000); err != nil {
			return
		}
	}
	log.Info("demo: generating live synthetic traffic")
	gen.Live(ctx, rec.Submit, 6*time.Second)
}

func prune(ctx context.Context, st *store.Store, keep time.Duration, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := st.Prune(ctx, time.Now().Add(-keep)); err != nil {
			log.Error("prune", "err", err)
		} else if n > 0 {
			log.Info("pruned old events", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
