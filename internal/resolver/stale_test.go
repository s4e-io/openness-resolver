package resolver

import (
	"strings"
	"testing"
	"time"
)

func TestMarkStale(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	ago := func(d float64) *time.Time { t := now.Add(-time.Duration(d * 24 * float64(time.Hour))); return &t }
	cov := RuleCoverage{Sources: []CoverageSource{
		{Source: "ubuntu-oval-usn-jammy", DownloadedAt: ago(3)},
		{Source: "debian-security-tracker", DownloadedAt: ago(1)},
		{Source: "msrc-cvrf-2026-Oct", DownloadedAt: ago(30)},
		{Source: "msrc-cvrf-2026-Sep", DownloadedAt: ago(40)},
		{Source: "app-mapper", DownloadedAt: ago(8)},
		{Source: "app-mapper-file", DownloadedAt: ago(6)},
		{Source: "osv-pypi", DownloadedAt: ago(400)},
		{Source: "app-mapper-builtin"},
	}}
	old := MarkStale(&cov, now, nil)
	if got := strings.Join(old, ", "); got != "ubuntu-oval-usn-jammy (3 days), msrc-cvrf-2026-Sep (40 days), app-mapper (8 days)" {
		t.Errorf("old = %s", got)
	}
	if s := cov.Sources[0]; *s.AgeDays != 3 || !*s.Stale {
		t.Errorf("jammy %+v", s)
	}
	if s := cov.Sources[6]; *s.AgeDays != 400 || *s.Stale {
		t.Errorf("pypi must never be old: %+v", s)
	}
	if s := cov.Sources[7]; s.AgeDays != nil || s.Stale != nil {
		t.Errorf("a source without downloaded_at has no age: %+v", s)
	}
	off := time.Duration(0)
	if old := MarkStale(&cov, now, &off); len(old) != 0 || *cov.Sources[0].Stale {
		t.Errorf("--stale-after 0: %v", old)
	}
	day := 24 * time.Hour
	if old := MarkStale(&cov, now, &day); len(old) != 6 {
		t.Errorf("--stale-after 1d marks every source older than a day, pypi too: %v", old)
	}
}
