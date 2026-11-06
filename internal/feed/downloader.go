// Package feed implements the advisory feed ingestion pipeline:
//
//	download -> checksum -> immutable raw storage -> parse -> normalize
//	-> validate -> version -> publish rules
//
// Raw feed files are stored unmodified under data/raw/<vendor>/<UTC date>/
// and previous snapshots are never deleted or overwritten, which keeps
// rollback possible at all times.
package feed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s4e-io/openness-resolver/internal/rules"
)

// Downloader fetches feed files over HTTPS with retry, conditional requests
// and atomic snapshot writes.
type Downloader struct {
	Client     *http.Client
	MaxRetries int
	Backoff    time.Duration
	// MaxWait caps one wait between tries. A server asking for more (Retry-After on a
	// 429 or 503, for example an hourly limit) is not waited for: the download fails.
	MaxWait time.Duration
	// DataDir is the root that holds raw/<vendor>/<date>/ snapshots.
	DataDir string
	Now     func() time.Time
	// Sleep waits between tries (time.Sleep; tests replace it).
	Sleep func(time.Duration)
}

// NewDownloader creates a Downloader with production defaults.
func NewDownloader(dataDir string) *Downloader {
	return &Downloader{
		Client:     &http.Client{Timeout: 120 * time.Second},
		MaxRetries: 3,
		Backoff:    2 * time.Second,
		MaxWait:    60 * time.Second,
		DataDir:    dataDir,
		Now:        time.Now,
		Sleep:      time.Sleep,
	}
}

// SnapshotResult describes one downloaded raw feed object.
type SnapshotResult struct {
	Meta        rules.FeedSourceMetadata
	Path        string // path of the raw immutable file
	NotModified bool
}

// snapshotState is persisted per source to support ETag/Last-Modified.
type snapshotState struct {
	ETag         string `json:"etag"`
	LastModified string `json:"last_modified"`
	SHA256       string `json:"sha256"`
	LatestPath   string `json:"latest_path"`
	SnapshotDir  string `json:"snapshot_dir"`
	DownloadedAt string `json:"downloaded_at"`
}

func (d *Downloader) stateFile(sourceID string) string {
	return filepath.Join(d.DataDir, "state", sourceID+".json")
}

// Fetch downloads one source into an immutable dated snapshot directory.
// If the server reports the content unchanged (ETag/Last-Modified), the
// previous snapshot is reused and NotModified is set.
func (d *Downloader) Fetch(src rules.AdvisorySource) (*SnapshotResult, error) {
	u, err := url.Parse(src.URL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("source %s: only https URLs are allowed (got %q)", src.ID, src.URL)
	}

	var prev snapshotState
	_ = readJSONFile(d.stateFile(src.ID), &prev)

	sleep := d.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	var lastErr error
	attempts := 0
	for attempt := 0; attempt <= d.MaxRetries; attempt++ {
		attempts++
		res, err := d.fetchOnce(src, prev)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if attempt == d.MaxRetries {
			break
		}
		wait := d.Backoff * time.Duration(1<<uint(attempt))
		var se *StatusError
		if errors.As(err, &se) {
			if !se.Retryable() {
				// 404, 403, ...: asking again gives the same answer.
				break
			}
			if se.RetryAfter >= 0 {
				wait = se.RetryAfter
			}
		}
		if d.MaxWait > 0 && wait > d.MaxWait {
			if se != nil && se.RetryAfter > d.MaxWait {
				lastErr = fmt.Errorf("%w (server asks to retry after %s)", err, se.RetryAfter)
				break
			}
			wait = d.MaxWait
		}
		sleep(wait)
	}
	return nil, fmt.Errorf("source %s: download failed after %d attempts: %w", src.ID, attempts, lastErr)
}

// StatusError is a download answered with an HTTP status other than 200 or 304.
type StatusError struct {
	Status int
	URL    string
	// RetryAfter is the server's Retry-After (delay seconds or HTTP date), -1 when absent.
	RetryAfter time.Duration
}

func (e *StatusError) Error() string { return fmt.Sprintf("http %d from %s", e.Status, e.URL) }

// Retryable: 408, 429 and 5xx are worth another try; other statuses are not.
func (e *StatusError) Retryable() bool {
	return e.Status == http.StatusRequestTimeout || e.Status == http.StatusTooManyRequests || e.Status >= 500
}

func statusError(resp *http.Response, url string, now time.Time) *StatusError {
	return &StatusError{Status: resp.StatusCode, URL: url, RetryAfter: ParseRetryAfter(resp.Header.Get("Retry-After"), now)}
}

// ParseRetryAfter reads a Retry-After value, delay seconds or an HTTP date; -1 when it is
// absent or unreadable, 0 for a time already past.
func ParseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return -1
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	} else {
		return -1
	}
	if d < 0 {
		d = 0
	}
	return d
}

func (d *Downloader) fetchOnce(src rules.AdvisorySource, prev snapshotState) (*SnapshotResult, error) {
	req, err := http.NewRequest(http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "openness-feed/1.0")
	if src.Format == "cvrf-json" {
		// MSRC returns XML unless JSON is requested explicitly.
		req.Header.Set("Accept", "application/json")
	}
	if prev.ETag != "" {
		req.Header.Set("If-None-Match", prev.ETag)
	}
	if prev.LastModified != "" {
		req.Header.Set("If-Modified-Since", prev.LastModified)
	}
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified && prev.LatestPath != "" {
		if _, err := os.Stat(prev.LatestPath); err == nil {
			meta := d.metaFromState(src, prev)
			return &SnapshotResult{Meta: meta, Path: prev.LatestPath, NotModified: true}, nil
		}
		// State said unchanged but the snapshot is gone; fall through to
		// a full re-download.
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotModified {
		return nil, statusError(resp, src.URL, d.Now())
	}
	if resp.StatusCode == http.StatusNotModified {
		// No usable previous copy: re-request unconditionally.
		req2, _ := http.NewRequest(http.MethodGet, src.URL, nil)
		req2.Header.Set("User-Agent", "openness-feed/1.0")
		if src.Format == "cvrf-json" {
			req2.Header.Set("Accept", "application/json")
		}
		resp2, err := d.Client.Do(req2)
		if err != nil {
			return nil, err
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			return nil, statusError(resp2, src.URL, d.Now())
		}
		resp = resp2
	}

	// Snapshot directory: data/raw/<vendor>/<timestamp>/ — never reused, so
	// a previous feed copy is never overwritten.
	now := d.Now().UTC()
	snapDir := filepath.Join(d.DataDir, "raw", src.Vendor, now.Format("2006-01-02T150405Z"))
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		return nil, err
	}
	fileName := filepath.Base(strings.Split(src.URL, "?")[0])
	finalPath := filepath.Join(snapDir, fileName)
	if _, err := os.Stat(finalPath); err == nil {
		// Two sources fetched within one second can share a file name
		// (main.json of two Alpine branches, updateinfo.xml.gz of two Amazon
		// releases); keep both raw objects instead of replacing one.
		fileName = src.ID + "-" + fileName
		finalPath = filepath.Join(snapDir, fileName)
	}

	// Atomic write: stream to temp file, hash while writing, rename.
	tmp, err := os.CreateTemp(snapDir, ".download-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	if err != nil {
		tmp.Close()
		return nil, fmt.Errorf("download body: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), finalPath); err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(h.Sum(nil))

	var srcUpdated *time.Time
	lm := resp.Header.Get("Last-Modified")
	if lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			srcUpdated = &t
		}
	}
	meta := rules.FeedSourceMetadata{
		SourceName:      src.ID,
		SourceURL:       src.URL,
		DownloadedAt:    now,
		SourceUpdatedAt: srcUpdated,
		SHA256:          sum,
		ETag:            resp.Header.Get("ETag"),
		SizeBytes:       size,
		RawObjectID:     filepath.Join(src.Vendor, now.Format("2006-01-02T150405Z"), fileName),
		SnapshotDir:     snapDir,
	}
	state := snapshotState{
		ETag:         meta.ETag,
		LastModified: lm,
		SHA256:       sum,
		LatestPath:   finalPath,
		SnapshotDir:  snapDir,
		DownloadedAt: now.Format(time.RFC3339),
	}
	if err := writeJSONFile(d.stateFile(src.ID), state); err != nil {
		return nil, err
	}
	// Persist metadata next to the raw object.
	if err := writeJSONFile(filepath.Join(snapDir, fileName+".meta.json"), meta); err != nil {
		return nil, err
	}
	return &SnapshotResult{Meta: meta, Path: finalPath}, nil
}

func (d *Downloader) metaFromState(src rules.AdvisorySource, st snapshotState) rules.FeedSourceMetadata {
	downloadedAt, _ := time.Parse(time.RFC3339, st.DownloadedAt)
	return rules.FeedSourceMetadata{
		SourceName:   src.ID,
		SourceURL:    src.URL,
		DownloadedAt: downloadedAt,
		SHA256:       st.SHA256,
		ETag:         st.ETag,
		RawObjectID:  strings.TrimPrefix(st.LatestPath, filepath.Join(d.DataDir, "raw")+string(os.PathSeparator)),
		SnapshotDir:  st.SnapshotDir,
	}
}

// Snapshots lists all stored raw snapshots for a vendor, newest first.
func (d *Downloader) Snapshots(vendor string) ([]string, error) {
	dir := filepath.Join(d.DataDir, "raw", vendor)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

// Metrics counts ingestion pipeline outcomes for one sync run.
type Metrics struct {
	RecordsDownloaded int `json:"records_downloaded"`
	RecordsParsed     int `json:"records_parsed"`
	RecordsNormalized int `json:"records_normalized"`
	RecordsRejected   int `json:"records_rejected"`
	PackagesSeen      int `json:"packages_seen"`
	ReleasesSeen      int `json:"releases_seen"`
	CVEsSeen          int `json:"cves_seen"`
	RulesGenerated    int `json:"rules_generated"`
	// RejectionReasons preserves why records were rejected; malformed feed
	// records are never skipped silently.
	RejectionReasons map[string]int `json:"rejection_reasons,omitempty"`
}

// Reject records one rejected record with its reason.
func (m *Metrics) Reject(reason string) {
	m.RecordsRejected++
	if m.RejectionReasons == nil {
		m.RejectionReasons = map[string]int{}
	}
	m.RejectionReasons[reason]++
}

func readJSONFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
