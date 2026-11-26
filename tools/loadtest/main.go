// Command loadtest drives the fixed load profile from the challenge sheet:
// create a pool of secrets, then push sustained read traffic and report p50/p95/
// p99 latency and achieved throughput.
//
// It is intentionally dependency-free so a reviewer can run it with `go run`
// against any build, not just ours.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type createResp struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

func main() {
	base := flag.String("base", "http://localhost:8080", "base URL of the service")
	rps := flag.Int("rps", 200, "target requests per second")
	dur := flag.Duration("duration", 60*time.Second, "load duration")
	pool := flag.Int("pool", 20000, "number of pre-created secrets to read from")
	concurrency := flag.Int("c", 64, "concurrent workers")
	flag.Parse()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        *concurrency * 2,
			MaxIdleConnsPerHost: *concurrency * 2,
			MaxConnsPerHost:     *concurrency * 2,
			DisableCompression:  true,
		},
	}

	fmt.Printf("creating %d secrets against %s ...\n", *pool, *base)
	ids := make([]string, 0, *pool)
	{
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 32)
		for i := 0; i < *pool; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				body, _ := json.Marshal(map[string]any{
					"content":     "load-test-payload",
					"ttl_seconds": 3600,
					"max_views":   1,
				})
				res, err := client.Post(*base+"/secrets", "application/json", bytes.NewReader(body))
				if err != nil {
					return
				}
				defer res.Body.Close()
				if res.StatusCode != http.StatusCreated {
					return
				}
				var c createResp
				if json.NewDecoder(res.Body).Decode(&c) == nil && c.ID != "" {
					mu.Lock()
					ids = append(ids, c.ID)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
	}
	if len(ids) == 0 {
		fmt.Fprintln(os.Stderr, "no secrets could be created; is the service up and the rate limit high enough?")
		os.Exit(1)
	}
	fmt.Printf("created %d secrets\n", len(ids))

	maxSamples := *rps * int(dur.Seconds()) * 2
	samples := make([]time.Duration, maxSamples)
	var sampleN atomic.Int64
	var ok, throttled, failed atomic.Int64
	var idx atomic.Int64

	deadline := time.Now().Add(*dur)

	var wg sync.WaitGroup
	// Pacing note: a single ticker shared by all workers is a trap on Windows,
	// where the timer granularity is ~15ms, so a 5ms ticker really fires ~64/s
	// and silently caps throughput. Each worker therefore owns its own ticker at
	// rps/workers, which keeps every period comfortably above the granularity.
	perWorker := float64(*rps) / float64(*concurrency)
	if perWorker <= 0 {
		perWorker = 1
	}
	period := time.Duration(float64(time.Second) / perWorker)

	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(period)
			defer t.Stop()
			for range t.C {
				if time.Now().After(deadline) {
					return
				}
				n := idx.Add(1)
				if int(n) >= len(ids) {
					return
				}
				id := ids[n]
				start := time.Now()
				req, _ := http.NewRequest(http.MethodGet, *base+"/s/"+id, nil)
				req.Header.Set("Accept", "application/json")
				res, err := client.Do(req)
				elapsed := time.Since(start)
				if err != nil {
					failed.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
				switch res.StatusCode {
				case http.StatusOK:
					ok.Add(1)
				case http.StatusTooManyRequests:
					throttled.Add(1)
				default:
					failed.Add(1)
				}
				if k := sampleN.Add(1); int(k) < len(samples) {
					samples[k-1] = elapsed
				}
			}
		}()
	}

	start := time.Now()
	time.Sleep(*dur)
	wg.Wait()
	elapsed := time.Since(start)

	n := int(sampleN.Load())
	if n > len(samples) {
		n = len(samples)
	}
	valid := samples[:n]
	sort.Slice(valid, func(i, j int) bool { return valid[i] < valid[j] })

	pct := func(p float64) time.Duration {
		if len(valid) == 0 {
			return 0
		}
		i := int(float64(len(valid)-1) * p)
		return valid[i]
	}

	fmt.Printf("\n--- results ---\n")
	fmt.Printf("duration        %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("ok              %d\n", ok.Load())
	fmt.Printf("throttled(429)  %d\n", throttled.Load())
	fmt.Printf("failed          %d\n", failed.Load())
	fmt.Printf("throughput      %.1f req/s\n", float64(ok.Load())/elapsed.Seconds())
	fmt.Printf("p50             %s\n", pct(0.50).Round(time.Microsecond))
	fmt.Printf("p95             %s\n", pct(0.95).Round(time.Microsecond))
	fmt.Printf("p99             %s\n", pct(0.99).Round(time.Microsecond))
	if n > 0 {
		fmt.Printf("p999            %s\n", pct(0.999).Round(time.Microsecond))
	}
}
