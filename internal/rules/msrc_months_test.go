package rules

import (
	"strings"
	"testing"
	"time"
)

// Windows coverage back to January 2023 needs 46 monthly documents in
// October 2026; the month walk must cross year boundaries cleanly and every
// id must pass the release validation used to build the URL.
func TestMSRCMonthsReachJanuary2023(t *testing.T) {
	now := time.Date(2026, time.October, 30, 23, 59, 0, 0, time.FixedZone("x", 3*3600))
	months := MSRCMonths(46, now)
	if len(months) != 46 || months[0] != "2026-Oct" || months[45] != "2023-Jan" {
		t.Fatalf("got %d months, first %s last %s", len(months), months[0], months[len(months)-1])
	}
	seen := map[string]bool{}
	for i, m := range months {
		if seen[m] {
			t.Fatalf("duplicate month %s", m)
		}
		seen[m] = true
		if _, err := ReleaseSources("microsoft", m); err != nil {
			t.Fatalf("month %s: %v", m, err)
		}
		if i > 0 && strings.HasSuffix(months[i-1], "-Jan") {
			prevYear := months[i-1][:4]
			if m[:4] == prevYear || !strings.HasSuffix(m, "-Dec") {
				t.Fatalf("year boundary after %s went to %s", months[i-1], m)
			}
		}
	}
	for _, want := range []string{"2025-Dec", "2025-Jan", "2024-Dec", "2024-Jan", "2023-Dec"} {
		if !seen[want] {
			t.Errorf("missing %s", want)
		}
	}
	srcs := MSRCSources(46, now)
	if len(srcs) != 46 || srcs[45].URL != "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2023-Jan" {
		t.Fatalf("sources %d, last %+v", len(srcs), srcs[len(srcs)-1])
	}
}

// Month ends must not skip or repeat a month (AddDate on the 31st would).
func TestMSRCMonthsFromMonthEnds(t *testing.T) {
	for _, now := range []time.Time{
		time.Date(2026, time.March, 31, 12, 0, 0, 0, time.UTC),
		time.Date(2024, time.March, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
	} {
		months := MSRCMonths(14, now)
		want := now.Format("2006-Jan")
		if months[0] != want {
			t.Fatalf("%v: first %s want %s", now, months[0], want)
		}
		seen := map[string]bool{}
		for _, m := range months {
			if seen[m] {
				t.Fatalf("%v: duplicate %s in %v", now, m, months)
			}
			seen[m] = true
		}
	}
	if got := MSRCMonths(0, time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC)); len(got) != 24 {
		t.Fatalf("default months %d", len(got))
	}
}
