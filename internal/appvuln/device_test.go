package appvuln

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The seed device entries of the built-in catalog read the sysDescr samples of
// testdata/devices (the shape each vendor documents for its sysDescr, sysObjectID and
// entPhysicalSoftwareRev). They are unreviewed: only Unverified uses them.
func TestSeedDeviceEntries(t *testing.T) {
	d, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]struct{ id, version string }{
		"cisco-ios-xe":      {"cisco.ios-xe", "17.9.4a"},
		"cisco-ios":         {"cisco.ios", "15.2(7)E7"},
		"cisco-nx-os":       {"cisco.nx-os", "9.3(8)"},
		"cisco-asa":         {"cisco.asa", "9.16(4)19"},
		"fortinet-fortios":  {"fortinet.fortios", "7.2.5"},
		"juniper-junos":     {"juniper.junos", "21.4R3-S5.4"},
		"mikrotik-routeros": {"mikrotik.routeros", "7.12.1"},
		"paloalto-pan-os":   {"paloaltonetworks.pan-os", "10.2.4-h4"},
		"aruba-aos-cx":      {"aruba.aos-cx", "10.10.1040"},
		"ubiquiti-edgeos":   {"ubiquiti.edgeos", "2.0.9"},
		"net-snmp-linux":    {},
	} {
		dev, err := ReadDeviceFile(filepath.Join("..", "..", "testdata", "devices", file+".json"))
		if err != nil {
			t.Fatal(err)
		}
		r := d.EvaluateDevice(dev, Options{Unverified: true})
		got := struct{ id, version string }{}
		if r.Product != nil {
			got.id, got.version = r.Product.ID, r.Version
		}
		if got != want {
			t.Errorf("%s: matched %q version %q, want %q %q", file, got.id, got.version, want.id, want.version)
		}
		if want.id == "" {
			continue
		}
		if r.Product.Verified {
			t.Errorf("%s: seed entry %s must stay unverified until an analyst reviews it", file, want.id)
		}
		if off := d.EvaluateDevice(dev, Options{}); off.Product != nil || off.Skipped == nil || off.Skipped.ID != want.id {
			t.Errorf("%s: without Unverified the entry must be skipped, got %+v", file, off)
		}
	}
	// device entries never match an application
	r := d.EvaluateApps([]json.RawMessage{json.RawMessage(`{"product_name":"Cisco IOS XE","display_version":"17.9.4"}`)}, Options{Unverified: true})
	for _, a := range r.Applications {
		if strings.HasPrefix(a.ProductID, "cisco.ios") {
			t.Errorf("application matched device entry %s", a.ProductID)
		}
	}
}

const deviceCatalog = `[
 {"id":"acme.os","name":"Acme OS","kind":"device","match":{"sys_object_id":"^\\.?1\\.3\\.6\\.1\\.4\\.1\\.99999\\.","sys_descr":"AcmeOS"},
  "version":{"from":"sys_descr","regex":"AcmeOS ([0-9.]+)"},"cpe":["acme:os"],"update":"Upgrade Acme OS.","verified":true},
 {"id":"future.thing","name":"Future","kind":"firmware_blob","match":{},"cpe":[]},
 {"id":"acme.tool","name":"Acme Tool","match":{"name":"^Acme Tool"},"cpe":["acme:tool"],"verified":true}]`

func TestEvaluateDevice(t *testing.T) {
	d, err := Load([]byte(deviceCatalog), []byte(`{"version":"t","products":{"acme:os":[
		{"cve":"CVE-2099-0001","sev":"high","cvss":8,"r":[{"ee":"2.0"}]},{"cve":"CVE-2099-0002","sev":"low","r":[{"ee":"1.0"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Catalog) != 2 {
		t.Fatalf("an entry of an unknown kind must be dropped, catalog %d", len(d.Catalog))
	}
	r := d.EvaluateDevice(Device{SysObjectID: ".1.3.6.1.4.1.99999.1", SysDescr: "AcmeOS 1.5 build 7"}, Options{})
	if r.Product == nil || r.Version != "1.5" || r.Rules != 2 || len(r.Findings) != 1 {
		t.Fatalf("result %+v", r)
	}
	f := r.Findings[0]
	if f.FindingID != "device:acme.os:1.5:CVE-2099-0001" || f.Scope != "network_device" || f.FixedVersion != "2.0" {
		t.Errorf("finding %+v", f)
	}
	if len(r.Remediations) != 1 || r.Remediations[0].CommandHint != "Upgrade Acme OS." || r.Remediations[0].Scope != "network_device" {
		t.Errorf("remediations %+v", r.Remediations)
	}
	// every match key must hold
	if r := d.EvaluateDevice(Device{SysObjectID: ".1.3.6.1.4.1.9.1", SysDescr: "AcmeOS 1.5"}, Options{}); r.Product != nil {
		t.Errorf("sys_object_id ignored: %+v", r.Product)
	}
	// a version the regex does not find: matched, no findings
	if r := d.EvaluateDevice(Device{SysObjectID: "1.3.6.1.4.1.99999.1", SysDescr: "AcmeOS beta"}, Options{}); r.Product == nil || r.Version != "" || len(r.Findings) != 0 {
		t.Errorf("version miss %+v", r)
	}
}

func TestDeviceEntryErrors(t *testing.T) {
	for name, entry := range map[string]string{
		"no match":   `{"id":"x","name":"x","kind":"device","match":{},"version":{"regex":"v(\\d+)"},"cpe":[]}`,
		"no group":   `{"id":"x","name":"x","kind":"device","match":{"sys_descr":"x"},"version":{"regex":"v\\d+"},"cpe":[]}`,
		"two groups": `{"id":"x","name":"x","kind":"device","match":{"sys_descr":"x"},"version":{"regex":"(v)(\\d+)"},"cpe":[]}`,
		"bad from":   `{"id":"x","name":"x","kind":"device","match":{"sys_descr":"x"},"version":{"from":"model","regex":"(\\d+)"},"cpe":[]}`,
		"bad regex":  `{"id":"x","name":"x","kind":"device","match":{"model":"("},"version":{"regex":"(\\d+)"},"cpe":[]}`,
	} {
		if _, err := Load([]byte("["+entry+"]"), []byte(`{"products":{}}`)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// A device file carries no host name or address: another field is refused.
func TestReadDevice(t *testing.T) {
	ok := `{"format":"openness-device/1","sys_descr":"AcmeOS 1.5","sys_object_id":".1.3.6.1.4.1.99999.1","model":"","software_rev":"","firmware_rev":"","hardware_rev":"","serial_hint":""}`
	if _, err := ReadDevice(strings.NewReader(ok)); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"host name":  `{"format":"openness-device/1","sys_descr":"x","sys_name":"core-sw1"}`,
		"address":    `{"format":"openness-device/1","sys_descr":"x","ip":"10.0.0.1"}`,
		"format":     `{"format":"openness-device/2","sys_descr":"x"}`,
		"not json":   `{`,
		"too large":  `{"format":"openness-device/1","sys_descr":"` + strings.Repeat("x", maxDeviceFile) + `"}`,
		"no format":  `{"sys_descr":"x"}`,
		"wrong type": `{"format":"openness-device/1","sys_descr":5}`,
	} {
		if _, err := ReadDevice(strings.NewReader(body)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(name, "host") || name == "address" {
			if !strings.Contains(err.Error(), "no host names or addresses") {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"Cisco IOS Software, Version 17.9.4a, RELEASE SOFTWARE (fc5)": "Cisco IOS Software, Version 17.9.4a, RELEASE SOFTWARE (fc5)",
		"JUNOS 21.4R3-S5.4 on core-sw1.corp.example.com":              "JUNOS 21.4R3-S5.4 on [redacted]",
		"switch at 10.20.30.40, mgmt fe80::1, 2001:db8::7.":           "switch at [redacted], mgmt [redacted], [redacted].",
		"EdgeOS v2.0.9-hotfix.7.5622731.230615.0857":                  "EdgeOS v2.0.9-hotfix.7.5622731.230615.0857",
		"Aruba JL658A 6300M Swch FL.10.10.1040":                       "Aruba JL658A 6300M Swch FL.10.10.1040",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
	if got := FirstLine("A 1.2\r\nTechnical Support: http://www.cisco.com"); got != "A 1.2" {
		t.Errorf("FirstLine %q", got)
	}
}

// syntheticBundle is a gzip mapper with n vulnerabilities over n/10 products.
func syntheticBundle(t testing.TB, n int) (path string, uncompressed int) {
	t.Helper()
	products := map[string][]Vuln{}
	var catalog []map[string]any
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("vendor%d:product%d", i/10, i/10)
		if i%10 == 0 {
			catalog = append(catalog, map[string]any{"id": key, "name": key, "match": map[string]string{"name": "^" + key + "$"}, "cpe": []string{key}, "verified": true})
		}
		products[key] = append(products[key], Vuln{CVE: fmt.Sprintf("CVE-2099-%06d", i), CVSS: 7.5, Severity: "high",
			Ranges: []Range{{StartIncl: "1.0", EndExcl: fmt.Sprintf("2.%d", i)}}})
	}
	cat, _ := json.Marshal(catalog)
	db, _ := json.Marshal(DB{Version: "synthetic", Products: products})
	var raw bytes.Buffer
	if err := WriteBundle(&raw, "synthetic-1", cat, db, []byte(`{"version":"f","products":{}}`)); err != nil {
		t.Fatal(err)
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write(raw.Bytes())
	zw.Close()
	path = filepath.Join(t.TempDir(), "app-mapper.json.gz")
	if err := os.WriteFile(path, z.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, raw.Len()
}

func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// peakHeap runs f with an eager garbage collector and returns the largest live heap seen
// while it ran, above what was live before.
func peakHeap(f func()) uint64 {
	old := debug.SetGCPercent(5)
	defer debug.SetGCPercent(old)
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	read := func() uint64 { metrics.Read(sample); return sample[0].Value.Uint64() }
	runtime.GC()
	base := read()
	var peak atomic.Uint64
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			if v := read(); v > peak.Load() {
				peak.Store(v)
			}
			select {
			case <-done:
				return
			case <-time.After(200 * time.Microsecond):
			}
		}
	}()
	f()
	close(done)
	<-stopped
	if p := peak.Load(); p > base {
		return p - base
	}
	return 0
}

// A bundle over MaxBundleSize is refused after reading just past the limit: memory stays
// bounded by the limit, not by the file.
func TestLoadFileRefusesLargeBundle(t *testing.T) {
	path, size := syntheticBundle(t, 50000)
	defer func(m int64) { MaxBundleSize = m }(MaxBundleSize)
	MaxBundleSize = 1 << 20
	var err error
	alloc := allocated(func() { _, err = LoadFile(path) })
	if err == nil || !strings.Contains(err.Error(), "larger than 1 MB uncompressed; refused") {
		t.Fatalf("err = %v", err)
	}
	if alloc > 16<<20 {
		t.Errorf("refusing a %d MB bundle allocated %d MB; the read must stop at the limit", size>>20, alloc>>20)
	}
}

// A 50k-vulnerability bundle loads by streaming: the decoder never holds the file or a
// whole database section, so loading allocates less than reading the file into memory and
// decoding it, and what stays on the heap is the decoded data.
func TestLoadFileLargeBundleStreams(t *testing.T) {
	path, size := syntheticBundle(t, 50000)
	var d *Data
	var err error
	streamed := peakHeap(func() { d, err = LoadFile(path) })
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, vs := range d.DB.Products {
		n += len(vs)
	}
	if n != 50000 || len(d.Catalog) != 5000 || d.Version != "synthetic-1" {
		t.Fatalf("loaded %d vulns, %d entries, version %q", n, len(d.Catalog), d.Version)
	}
	// the old way: the whole file, then the whole document, in memory, then the same decode
	whole := peakHeap(func() {
		raw, _ := os.ReadFile(path)
		zr, _ := gzip.NewReader(bytes.NewReader(raw))
		var buf bytes.Buffer
		buf.ReadFrom(zr)
		var b Bundle
		json.Unmarshal(buf.Bytes(), &b)
		old, _ := Load(b.Catalog, b.Vulns)
		runtime.KeepAlive(old)
		runtime.KeepAlive(raw)
		runtime.KeepAlive(&buf)
	})
	t.Logf("bundle %.1f MB uncompressed: peak heap of the streaming load %.1f MB, of a whole-file load %.1f MB",
		float64(size)/(1<<20), float64(streamed)/(1<<20), float64(whole)/(1<<20))
	if streamed >= whole {
		t.Errorf("streaming load peaked at %d bytes, not below the whole-file load (%d)", streamed, whole)
	}
	runtime.KeepAlive(d)
}

func BenchmarkLoadFile50k(b *testing.B) {
	path, _ := syntheticBundle(b, 50000)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := LoadFile(path); err != nil {
			b.Fatal(err)
		}
	}
}
