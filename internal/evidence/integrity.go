package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Integrity states reported in LoadResult.Integrity and asset.evidence_integrity.
const (
	// IntegrityVerified: integrity.payload_hash matched the document.
	IntegrityVerified = "verified"
	// IntegrityAbsent: the document carries no payload hash (older collectors).
	IntegrityAbsent = "not_present"
)

// IntegrityAbsentNote is the run note for evidence without a payload hash.
const IntegrityAbsentNote = "evidence has no integrity.payload_hash; the file was not integrity checked (older collector)"

// zeroIntegrity is the collector's IntegrityInfo{} as JSON: the hash is computed
// over the document with this object in place of the real one.
const zeroIntegrity = `{"algorithm":"","payload_hash":"","signature":"","signing_key_id":""}`

type integrityInfo struct {
	Algorithm   string `json:"algorithm"`
	PayloadHash string `json:"payload_hash"`
}

// VerifyPayloadHash checks integrity.payload_hash of a raw .openness document the
// way the collector computes it: SHA-256 over the document with integrity zeroed,
// re-encoded as encoding/json encodes a generic value (sorted keys, compact,
// numbers as float64). It returns IntegrityAbsent when the document has no hash
// and an error when the hash or the algorithm does not match.
func VerifyPayloadHash(raw []byte) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return "", fmt.Errorf("decode .openness document: %w", err)
	}
	var info integrityInfo
	if r, ok := top["integrity"]; ok {
		_ = json.Unmarshal(r, &info)
	}
	want := strings.ToLower(strings.TrimSpace(info.PayloadHash))
	if want == "" {
		return IntegrityAbsent, nil
	}
	if info.Algorithm != "" && info.Algorithm != "SHA-256" {
		return "", fmt.Errorf("evidence integrity check failed: unsupported integrity.algorithm %q", info.Algorithm)
	}
	top["integrity"] = json.RawMessage(zeroIntegrity)
	h := sha256.New()
	if err := writeCanonicalObject(h, top); err != nil {
		return "", fmt.Errorf("evidence integrity check failed: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("evidence integrity check failed: integrity.payload_hash does not match the content (expected %s, computed %s); the file was changed or damaged after collection", want, got)
	}
	return IntegrityVerified, nil
}

// writeCanonical writes v as json.Marshal would write it after a round trip
// through any. Objects and arrays are walked one level at a time, so a large
// document is not expanded into a generic tree at once.
func writeCanonical(w io.Writer, v json.RawMessage) error {
	v = bytes.TrimSpace(v)
	if len(v) == 0 {
		return fmt.Errorf("empty JSON value")
	}
	switch v[0] {
	case '{':
		var m map[string]json.RawMessage
		if err := json.Unmarshal(v, &m); err != nil {
			return err
		}
		return writeCanonicalObject(w, m)
	case '[':
		var a []json.RawMessage
		if err := json.Unmarshal(v, &a); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "["); err != nil {
			return err
		}
		for i, e := range a {
			if i > 0 {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			if err := writeCanonical(w, e); err != nil {
				return err
			}
		}
		_, err := io.WriteString(w, "]")
		return err
	case '"':
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return err
		}
		return writeMarshal(w, s)
	case 't', 'f', 'n':
		_, err := w.Write(v)
		return err
	default:
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			return err
		}
		return writeMarshal(w, f)
	}
}

func writeCanonicalObject(w io.Writer, m map[string]json.RawMessage) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	for i, k := range keys {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := writeMarshal(w, k); err != nil {
			return err
		}
		if _, err := io.WriteString(w, ":"); err != nil {
			return err
		}
		if err := writeCanonical(w, m[k]); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "}")
	return err
}

func writeMarshal(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
