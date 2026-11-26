// Command otss runs the one-time secret service.
//
// Design in one line: secrets live only in RAM, sealed with AES-256-GCM under a
// per-secret key wrapped by a master key derived from the secret id and the
// passphrase, so neither a disk dump nor a log dump nor a wrong passphrase can
// recover anything.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Ale0011/otss/internal/api"
	"github.com/Ale0011/otss/internal/audit"
	"github.com/Ale0011/otss/internal/envelope"
	"github.com/Ale0011/otss/internal/metrics"
	"github.com/Ale0011/otss/internal/store"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("otss ")

	// The runtime image is distroless and has no shell, so the container health
	// check is this same binary in a special mode: probe /healthz and exit.
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}

	master, err := loadMasterKey()
	if err != nil {
		log.Fatalf("master key: %v", err)
	}
	sealer, err := envelope.New(master)
	envelope.Zero(master)
	if err != nil {
		log.Fatalf("sealer: %v", err)
	}

	cfg := api.Config{
		PublicBaseURL: os.Getenv("PUBLIC_BASE_URL"),
		TrustedProxy:  os.Getenv("TRUSTED_PROXIES"),
		MetricsToken:  os.Getenv("METRICS_TOKEN"),
		CreateRate:    envFloat("CREATE_RATE", 10),
		CreateBurst:   envFloat("CREATE_BURST", 20),
		ReadRate:      envFloat("READ_RATE", 50),
		ReadBurst:     envFloat("READ_BURST", 100),
	}

	st := store.New()
	au := audit.New(os.Stdout)
	m := metrics.New()

	srv := api.New(cfg, sealer, st, au, m)

	stopJanitor := make(chan struct{})
	go st.Janitor(30*time.Second, stopJanitor)

	addr := ":" + envStr("PORT", "8080")
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ErrorLog: log.New(os.Stderr, "otss http ", log.LstdFlags|log.LUTC),
	}

	// Lifecycle logs only — never secret, passphrase, token, or raw id.
	log.Printf("listening on %s", addr)
	if cfg.PublicBaseURL == "" {
		log.Printf("PUBLIC_BASE_URL unset; share links fall back to localhost only (set it in any real deploy)")
	}
	if cfg.MetricsToken == "" {
		log.Printf("METRICS_TOKEN unset; /metrics is open")
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	case sig := <-sigCh:
		log.Printf("signal %s received, shutting down", sig)
	}

	close(stopJanitor)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	// Every secret dies with the process. That is a feature.
	log.Printf("stopped")
}

// loadMasterKey reads MASTER_KEY (base64, 32 bytes) or fails hard.
//
// There is no "generate one if missing" path in production: silently generating
// a key would make every restart lose all secrets with no signal, and would hide
// a misconfigured deployment. Tests set the variable explicitly.
func loadMasterKey() ([]byte, error) {
	raw := os.Getenv("MASTER_KEY")
	if raw == "" {
		return nil, errors.New("MASTER_KEY is required (32 random bytes, base64)")
	}
	for _, enc := range []func(string) ([]byte, error){b64Std, b64Raw, b64URL, b64URLRaw} {
		if b, err := enc(raw); err == nil && len(b) == envelope.MasterKeyLen {
			return b, nil
		}
	}
	return nil, errors.New("MASTER_KEY must decode to exactly 32 bytes")
}

func b64Std(s string) ([]byte, error)    { return base64.StdEncoding.DecodeString(s) }
func b64Raw(s string) ([]byte, error)    { return base64.RawStdEncoding.DecodeString(s) }
func b64URL(s string) ([]byte, error)    { return base64.URLEncoding.DecodeString(s) }
func b64URLRaw(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func envStr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envFloat(k string, def float64) float64 {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 {
		return def
	}
	return f
}

// healthcheck probes /healthz on the local port and exits non-zero on failure.
// Used as the container health check because the runtime image has no shell.
func healthcheck() int {
	port := envStr("PORT", "8080")
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
