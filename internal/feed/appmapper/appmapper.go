// Package appmapper syncs the application and device mapper (format openness-app-mapper/1)
// as an ordinary feed source: the catalog by S4E plus the NVD data of its products, which
// the S4E backend publishes as a release asset of a public GitHub repository. Nothing is
// needed to download it: no account, no key.
//
// The bundle is checked against the SHA256SUMS file of the same release, loaded once to
// prove it is a mapper this build reads, and only then put in place at
// <data-dir>/mapper/app-mapper.json.gz with its metadata next to it.
package appmapper

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/s4e-io/openness-resolver/internal/appvuln"
)

// ID is the source id.
const ID = "app-mapper"

// ErrNotPublished: the release location answered 404.
var ErrNotPublished = errors.New("not published yet")

// Client downloads the mapper; a large bundle on a slow link needs more than the feed
// downloader's timeout.
var Client = &http.Client{Timeout: 15 * time.Minute}

// Path is where the synced mapper of a data directory is kept.
func Path(dataDir string) string {
	return filepath.Join(dataDir, "mapper", "app-mapper.json.gz")
}

// SumsURL is the SHA256SUMS file next to the bundle URL.
func SumsURL(bundleURL string) string {
	i := strings.LastIndex(bundleURL, "/")
	return bundleURL[:i+1] + "SHA256SUMS"
}

// Sync downloads the bundle at bundleURL, verifies its sha256 against SHA256SUMS and loads
// it. With publish it replaces <data-dir>/mapper/app-mapper.json.gz and writes the
// metadata; without (feed validate) the download is discarded.
func Sync(bundleURL, dataDir string, publish bool, now time.Time) (appvuln.BundleMeta, error) {
	u, err := url.Parse(bundleURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return appvuln.BundleMeta{}, fmt.Errorf("%s: not an http(s) URL: %q", ID, bundleURL)
	}
	name := path.Base(u.Path)
	want, err := expectedSum(SumsURL(bundleURL), name)
	if err != nil {
		return appvuln.BundleMeta{}, err
	}
	dst := Path(dataDir)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return appvuln.BundleMeta{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".download-*")
	if err != nil {
		return appvuln.BundleMeta{}, err
	}
	defer os.Remove(tmp.Name())
	sum, size, err := download(bundleURL, tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return appvuln.BundleMeta{}, err
	}
	if !strings.EqualFold(sum, want) {
		return appvuln.BundleMeta{}, fmt.Errorf("%s: sha256 %s of %s does not match SHA256SUMS (%s)", ID, sum, name, want)
	}
	d, err := appvuln.LoadFile(tmp.Name())
	if err != nil {
		return appvuln.BundleMeta{}, err
	}
	meta := appvuln.BundleMeta{Source: ID, SourceURL: bundleURL, DownloadedAt: now.UTC(), SHA256: sum,
		SizeBytes: size, Format: appvuln.BundleFormat, Version: d.Version}
	if !publish {
		return meta, nil
	}
	return meta, Install(tmp.Name(), dst, meta)
}

// Install moves a checked bundle to dst and writes its metadata next to it.
func Install(src, dst string, meta appvuln.BundleMeta) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	return WriteMeta(dst, meta)
}

// WriteMeta writes the metadata of the bundle at bundle.
func WriteMeta(bundle string, meta appvuln.BundleMeta) error {
	raw, err := jsonIndent(meta)
	if err != nil {
		return err
	}
	tmp := appvuln.MetaPath(bundle) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, appvuln.MetaPath(bundle))
}

func get(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "openness-feed/1.0")
	resp, err := Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ID, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound:
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %w: %s answered 404 (the S4E catalog has not published the mapper there yet; resolve keeps using the mapper it has)", ID, ErrNotPublished, rawURL)
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("%s: http %d from %s", ID, resp.StatusCode, rawURL)
	}
}

// expectedSum reads the sha256 of file name from a SHA256SUMS file
// ("<hex>  <name>" or "<hex> *<name>" lines).
func expectedSum(sumsURL, name string) (string, error) {
	resp, err := get(sumsURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("%s: %s: %w", ID, sumsURL, err)
	}
	return "", fmt.Errorf("%s: %s has no sha256 for %s", ID, sumsURL, name)
}

// download streams the bundle into w, hashing it, and refuses one larger than
// appvuln.MaxBundleSize (the compressed file is never larger than its content).
func download(rawURL string, w io.Writer) (string, int64, error) {
	resp, err := get(rawURL)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, appvuln.MaxBundleSize+1))
	if err != nil {
		return "", n, fmt.Errorf("%s: download: %w", ID, err)
	}
	if n > appvuln.MaxBundleSize {
		return "", n, fmt.Errorf("%s: %s is larger than %d MB; refused", ID, rawURL, appvuln.MaxBundleSize>>20)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func jsonIndent(v any) ([]byte, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	return append(raw, '\n'), err
}
