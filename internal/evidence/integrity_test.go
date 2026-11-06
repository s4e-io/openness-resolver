package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// collectorHash mirrors the collector's evidencefile.PayloadHash: marshal the
// document with zeroed integrity, round-trip through any, marshal again.
func collectorHash(t *testing.T, doc map[string]any) string {
	t.Helper()
	tmp := map[string]any{}
	for k, v := range doc {
		tmp[k] = v
	}
	tmp["integrity"] = struct {
		Algorithm    string `json:"algorithm"`
		PayloadHash  string `json:"payload_hash"`
		Signature    string `json:"signature"`
		SigningKeyID string `json:"signing_key_id"`
	}{}
	raw, err := json.Marshal(tmp)
	if err != nil {
		t.Fatal(err)
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:])
}

func sampleDoc() map[string]any {
	return map[string]any{
		"schema_version": "1.6.0",
		"collector":      map[string]any{"name": "openness", "version": "0.9.0"},
		"asset":          map[string]any{"asset_id": "a1", "hostname": "h<&>é "},
		"collection":     map[string]any{"duration_ms": int64(1234567890123), "partial": true},
		"operating_system": map[string]any{
			"distribution_id": "ubuntu", "version_id": "22.04", "ratio": 0.1, "big": 1.5e300, "nothing": nil,
		},
		"packages": []any{map[string]any{"value": map[string]any{"name": "bash", "raw_version_string": "5.1", "relationships": []any{}}}},
		"modules":  []any{map[string]any{"module_id": "packages", "status": "ok", "errors": []any{}, "evidence": map[string]any{}}},
		"errors":   []any{},
	}
}

func writeDoc(t *testing.T, doc map[string]any, integrity map[string]any) string {
	t.Helper()
	out := map[string]any{}
	for k, v := range doc {
		out[k] = v
	}
	if integrity != nil {
		out["integrity"] = integrity
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host.openness")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPayloadHash(t *testing.T) {
	doc := sampleDoc()
	good := collectorHash(t, doc)
	tampered := sampleDoc()
	tampered["asset"].(map[string]any)["hostname"] = "other"
	cases := []struct {
		name      string
		doc       map[string]any
		integrity map[string]any
		want      string
		err       string
	}{
		{name: "matches the collector", doc: doc, integrity: map[string]any{"algorithm": "SHA-256", "payload_hash": good, "signature": "", "signing_key_id": ""}, want: IntegrityVerified},
		{name: "upper-case hex", doc: doc, integrity: map[string]any{"algorithm": "SHA-256", "payload_hash": strings.ToUpper(good)}, want: IntegrityVerified},
		{name: "content changed", doc: tampered, integrity: map[string]any{"algorithm": "SHA-256", "payload_hash": good}, err: "payload_hash does not match"},
		{name: "garbage hash", doc: doc, integrity: map[string]any{"algorithm": "SHA-256", "payload_hash": "0000"}, err: "payload_hash does not match"},
		{name: "unsupported algorithm", doc: doc, integrity: map[string]any{"algorithm": "MD5", "payload_hash": good}, err: "unsupported integrity.algorithm"},
		{name: "empty hash", doc: doc, integrity: map[string]any{"algorithm": "SHA-256", "payload_hash": ""}, want: IntegrityAbsent},
		{name: "no integrity object", doc: doc, want: IntegrityAbsent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeDoc(t, tc.doc, tc.integrity)
			lr, err := Load(path)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) || !strings.Contains(err.Error(), path) {
					t.Fatalf("Load error %v, want %q naming %s", err, tc.err, path)
				}
				if _, _, perr := RunPreflight(path, PreflightExpectations{}); perr == nil || !strings.Contains(perr.Error(), tc.err) {
					t.Fatalf("RunPreflight error %v, want %q", perr, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if lr.Integrity != tc.want {
				t.Fatalf("integrity %q, want %q", lr.Integrity, tc.want)
			}
			_, pres, err := RunPreflight(path, PreflightExpectations{})
			if err != nil || pres.Integrity != tc.want {
				t.Fatalf("RunPreflight %v %+v, want %q", err, pres, tc.want)
			}
		})
	}
}
