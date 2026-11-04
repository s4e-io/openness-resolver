package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// RulesFormat names the normalized rule layout (normalized/<vendor>/<release>/rules.json and
// metadata.json, PackageVulnerabilityRule). Bump it when either changes shape.
const RulesFormat = "openness-rules/1"

// FormatInfo says which processed rules this build reads and writes: rules built by another
// build with the same ID are interchangeable with its own `rules import` output, so a data
// mirror can ship them ready to use.
type FormatInfo struct {
	Format  string            `json:"format"`
	ID      string            `json:"id"`
	Parsers map[string]string `json:"parsers"`
}

// Format is the FormatInfo of a set of parser versions (name -> version). The ID is the
// first 12 hex digits of the sha256 of the format and the sorted name=version pairs, so it
// changes when the layout or any parser changes.
func Format(parsers map[string]string) FormatInfo {
	names := make([]string, 0, len(parsers))
	for n := range parsers {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(RulesFormat)
	for _, n := range names {
		b.WriteString("\n" + n + "=" + parsers[n])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return FormatInfo{Format: RulesFormat, ID: hex.EncodeToString(sum[:])[:12], Parsers: parsers}
}
