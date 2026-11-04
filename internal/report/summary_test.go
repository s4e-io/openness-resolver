package report

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/resolver"
)

func TestMissingCoverageTitleUsesGaps(t *testing.T) {
	cov := resolver.RuleCoverage{
		AssetRelease: "ubuntu/jammy",
		Gaps: []resolver.CoverageGap{{
			Release: "alpine/v3.19",
			Kind:    resolver.GapMissingRules,
		}},
	}
	if got := missingCoverageTitle(cov); got != "alpine/v3.19" {
		t.Fatalf("title=%q", got)
	}
}
