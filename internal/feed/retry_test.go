package feed

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

// retryServer answers status (with Retry-After when set) for the first n requests, then
// 200.
func retryServer(t *testing.T, n int64, status int, retryAfter string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= n {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(status)
			return
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func testDownloader(t *testing.T, srv *httptest.Server) (*Downloader, *[]time.Duration) {
	var sleeps []time.Duration
	d := &Downloader{Client: srv.Client(), DataDir: t.TempDir(), MaxRetries: 4, Backoff: time.Second, MaxWait: time.Minute,
		Now: time.Now, Sleep: func(d time.Duration) { sleeps = append(sleeps, d) }}
	return d, &sleeps
}

func TestFetchHonoursRetryAfterOn429(t *testing.T) {
	srv, calls := retryServer(t, 2, http.StatusTooManyRequests, "7")
	d, sleeps := testDownloader(t, srv)
	if _, err := d.Fetch(rules.AdvisorySource{ID: "osv-pypi", Vendor: "pypi", URL: srv.URL + "/osv-pypi/all.zip"}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || len(*sleeps) != 2 || (*sleeps)[0] != 7*time.Second || (*sleeps)[1] != 7*time.Second {
		t.Fatalf("calls %d sleeps %v", calls.Load(), *sleeps)
	}
}

func TestFetchBacksOffOn5xx(t *testing.T) {
	srv, _ := retryServer(t, 2, http.StatusServiceUnavailable, "")
	d, sleeps := testDownloader(t, srv)
	if _, err := d.Fetch(rules.AdvisorySource{ID: "x", Vendor: "x", URL: srv.URL + "/f"}); err != nil {
		t.Fatal(err)
	}
	if len(*sleeps) != 2 || (*sleeps)[0] != time.Second || (*sleeps)[1] != 2*time.Second {
		t.Fatalf("sleeps %v", *sleeps)
	}
}

func TestFetchGivesUpWhenRetryAfterIsTooLong(t *testing.T) {
	srv, calls := retryServer(t, 100, http.StatusTooManyRequests, "3600")
	d, sleeps := testDownloader(t, srv)
	_, err := d.Fetch(rules.AdvisorySource{ID: "x", Vendor: "x", URL: srv.URL + "/f"})
	if err == nil || !strings.Contains(err.Error(), "http 429") || !strings.Contains(err.Error(), "retry after 1h0m0s") {
		t.Fatalf("err %v", err)
	}
	if calls.Load() != 1 || len(*sleeps) != 0 {
		t.Fatalf("calls %d sleeps %v: an hourly limit is not waited for", calls.Load(), *sleeps)
	}
}

func TestFetchDoesNotRetry404(t *testing.T) {
	srv, calls := retryServer(t, 100, http.StatusNotFound, "")
	d, _ := testDownloader(t, srv)
	_, err := d.Fetch(rules.AdvisorySource{ID: "x", Vendor: "x", URL: srv.URL + "/f"})
	if err == nil || !strings.Contains(err.Error(), "http 404") || calls.Load() != 1 {
		t.Fatalf("err %v calls %d", err, calls.Load())
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{
		"": -1, "x": -1, "5": 5 * time.Second, "-1": 0,
		"Thu, 05 Nov 2026 12:00:30 GMT": 30 * time.Second,
	} {
		if got := ParseRetryAfter(in, now); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}
