package main

// Shared harness for the CLI tests: the tests build the real binary once and
// run it as a subprocess, so exit codes, stdout, stderr and flag parsing are
// exercised exactly as a user sees them, on Linux and on Windows.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata/golden")

// binPath is the openness binary built by TestMain.
var binPath string

// repoRoot is the repository root, relative to this package directory.
const repoRoot = "../.."

func TestMain(m *testing.M) {
	flag.Parse()
	dir, err := os.MkdirTemp("", "openness-cli-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	name := "openness"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binPath = filepath.Join(dir, name)
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build openness:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	if sharedFx.dir != "" {
		os.RemoveAll(sharedFx.dir)
	}
	os.Exit(code)
}

// cliResult is one run of the binary.
type cliResult struct {
	Code   int
	Stdout string
	Stderr string
}

// offlineEnv is the environment of every offline run: no OPENNESS_* variable
// from the developer's shell, and HTTP(S) proxies pointing at a closed port, so a
// run that tries to reach the internet fails instead of passing by luck.
// Loopback addresses bypass the proxy, so a local httptest mirror still works.
func offlineEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		up := strings.ToUpper(name)
		if strings.HasPrefix(up, "OPENNESS_") || strings.HasSuffix(up, "_PROXY") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"HTTP_PROXY=http://127.0.0.1:9", "HTTPS_PROXY=http://127.0.0.1:9",
		"http_proxy=http://127.0.0.1:9", "https_proxy=http://127.0.0.1:9",
		"NO_PROXY=", "no_proxy=")
	return append(env, extra...)
}

// runCLI runs the binary in dir (the package directory when empty) with env.
func runCLI(t *testing.T, dir string, env []string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Dir = dir
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := cliResult{Stdout: stdout.String(), Stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		res.Code = exit.ExitCode()
	default:
		t.Fatalf("run %v: %v", args, err)
	}
	return res
}

// run is runCLI offline, in the package directory.
func run(t *testing.T, args ...string) cliResult {
	t.Helper()
	return runCLI(t, "", offlineEnv(), args...)
}

// fixture is the absolute OS path of a repository file, for arguments; it
// stays valid when a case runs the binary in another working directory.
func fixture(rel string) string {
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		panic(err)
	}
	return filepath.Join(root, filepath.FromSlash(rel))
}

func evidencePath(name string) string {
	return fixture("testdata/evidence/synthetic/" + name + ".openness")
}

// osvMirror is a local stand-in for api.osv.dev/v1/query. It answers PyPI
// package queries from testdata/raw/osv and records the request headers.
type osvMirror struct {
	*httptest.Server
	headers []http.Header
}

func newOSVMirror(t *testing.T) *osvMirror {
	t.Helper()
	m := &osvMirror{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.headers = append(m.headers, r.Header.Clone())
		var q struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
		}
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || json.Unmarshal(body, &q) != nil || q.Package.Ecosystem != "PyPI" {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(fixture("testdata/raw/osv/pypi-1786369880/" + q.Package.Name + ".json"))
		if err != nil {
			data = []byte("{}")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *osvMirror) queryURL() string { return m.URL + "/v1/query" }
