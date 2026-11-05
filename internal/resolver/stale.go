package resolver

import (
	"fmt"
	"strings"
	"time"
)

// Default ages after which data counts as old, by source. Distribution feeds and the PyPI
// archive (osv-pypi) change several times a day, MSRC once a month, the application
// mapper daily.
const (
	StaleAfterFeed   = 2 * 24 * time.Hour
	StaleAfterMSRC   = 35 * 24 * time.Hour
	StaleAfterMapper = 7 * 24 * time.Hour
)

// DefaultStaleAfter is how old the data of a source may be; 0 means it never counts as old.
func DefaultStaleAfter(source string) time.Duration {
	switch {
	case strings.HasPrefix(source, "msrc-"):
		return StaleAfterMSRC
	case strings.HasPrefix(source, "app-mapper"):
		return StaleAfterMapper
	}
	return StaleAfterFeed
}

// MarkStale fills age_days and stale on every source with a downloaded_at, and returns a
// description of each old one ("ubuntu-oval-usn-jammy (5 days)"). override, when set,
// replaces every default; 0 turns the check off (ages are still filled).
func MarkStale(cov *RuleCoverage, now time.Time, override *time.Duration) []string {
	var old []string
	for i := range cov.Sources {
		s := &cov.Sources[i]
		if s.DownloadedAt == nil {
			continue
		}
		age := now.Sub(*s.DownloadedAt)
		if age < 0 {
			age = 0
		}
		days := int(age / (24 * time.Hour))
		limit := DefaultStaleAfter(s.Source)
		if override != nil {
			limit = *override
		}
		stale := limit > 0 && age > limit
		s.AgeDays, s.Stale = &days, &stale
		if stale {
			unit := "days"
			if days == 1 {
				unit = "day"
			}
			old = append(old, fmt.Sprintf("%s (%d %s)", s.Source, days, unit))
		}
	}
	return old
}
