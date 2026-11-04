package resolver

import (
	"strings"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

// T04: a package installed from the Ubuntu archive keeps high confidence and
// vendor provenance.
func TestVendorProvenanceKeepsHighConfidence(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("libssl3", "3.0.2-0ubuntu1.15",
			tf.WithSource("openssl"),
			tf.WithRepo("Ubuntu", "jammy-updates", "main", "http://ports.ubuntu.com/ubuntu-ports", "matched_apt_lists"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", "released", "3.0.2-0ubuntu1.16"))
	f := mustFinding(t, res, "libssl3", "CVE-1")
	if f.State != findings.StateVulnerable || f.Confidence != "high" {
		t.Errorf("state=%s confidence=%s", f.State, f.Confidence)
	}
	if f.Provenance != "vendor" || f.RepositoryComponent != "main" {
		t.Errorf("provenance=%q component=%q", f.Provenance, f.RepositoryComponent)
	}
}

// T04: third-party origin keeps the deterministic state but downgrades
// confidence, with the reason recorded.
func TestThirdPartyProvenanceDowngradesConfidence(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("libssl3", "3.0.2-0ubuntu1.15",
			tf.WithSource("openssl"),
			tf.WithRepo("SomeVendor", "stable", "main", "https://pkg.example.com", "matched_apt_lists"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", "released", "3.0.2-0ubuntu1.16"))
	f := mustFinding(t, res, "libssl3", "CVE-1")
	if f.State != findings.StateVulnerable {
		t.Errorf("state must stay deterministic: %s", f.State)
	}
	if f.Provenance != "third_party" || f.Confidence != "medium" {
		t.Errorf("provenance=%q confidence=%q", f.Provenance, f.Confidence)
	}
}

// T04 safety rule: unknown origin is never treated as local; the vendor rule
// still applies. Absence from apt indexes is expected for superseded
// (outdated) vendor packages, so it is labeled but does not downgrade
// confidence — only affirmative third-party evidence does.
func TestUnknownProvenanceNotTreatedAsLocal(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("libssl3", "3.0.2-0ubuntu1.15",
			tf.WithSource("openssl"),
			tf.WithRepo("", "", "", "", "not_in_apt_lists"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", "released", "3.0.2-0ubuntu1.16"))
	f := mustFinding(t, res, "libssl3", "CVE-1")
	if f.State != findings.StateVulnerable {
		t.Errorf("unknown origin must not suppress the vendor rule: %s", f.State)
	}
	if f.Provenance != "unknown" || f.Confidence != "high" {
		t.Errorf("provenance=%q confidence=%q", f.Provenance, f.Confidence)
	}
	found := false
	for _, r := range f.Reasons {
		if strings.Contains(r, "not treated as local") {
			found = true
		}
	}
	if !found {
		t.Errorf("provenance reason must be recorded: %v", f.Reasons)
	}
}

// No repository evidence collected at all: no provenance classification and
// no downgrade (missing evidence is not a negative signal).
func TestNoRepoEvidenceNoDowngrade(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("libssl3", "3.0.2-0ubuntu1.15", tf.WithSource("openssl"))
	res := resolve(t, doc, tf.UbuntuRule("CVE-1", "jammy", "openssl", "libssl3", "released", "3.0.2-0ubuntu1.16"))
	f := mustFinding(t, res, "libssl3", "CVE-1")
	if f.Provenance != "" || f.Confidence != "high" {
		t.Errorf("provenance=%q confidence=%q", f.Provenance, f.Confidence)
	}
}

// T05: an ESM-pocket fix is requires_esm when no entitlement evidence exists.
func TestESMFixWithoutEntitlement(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("libjs-jquery-ui", "1.13.1+dfsg-1", tf.WithSource("jqueryui"))
	r := tf.UbuntuRule("CVE-2", "jammy", "jqueryui", "libjs-jquery-ui", "released", "1.13.1+dfsg-1ubuntu0.1~esm1")
	r.SupportTier = "esm-apps"
	res := resolve(t, doc, r)
	f := mustFinding(t, res, "libjs-jquery-ui", "CVE-2")
	if f.FixAvailability != findings.FixRequiresESM {
		t.Errorf("fix availability=%q, want requires_esm", f.FixAvailability)
	}
}

// T05: entitlement is proven by packages actually installed from
// esm.ubuntu.com; the ESM fix then becomes available.
func TestESMFixWithEntitlement(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("some-esm-pkg", "1.0-1ubuntu0.1~esm2",
			tf.WithSource("some-esm-pkg"),
			tf.WithRepo("UbuntuESMApps", "jammy-apps-security", "main", "https://esm.ubuntu.com/apps/ubuntu", "matched_apt_lists")).
		AddPackage("libjs-jquery-ui", "1.13.1+dfsg-1", tf.WithSource("jqueryui"))
	r := tf.UbuntuRule("CVE-2", "jammy", "jqueryui", "libjs-jquery-ui", "released", "1.13.1+dfsg-1ubuntu0.1~esm1")
	r.SupportTier = "esm-apps"
	res := resolve(t, doc, r)
	f := mustFinding(t, res, "libjs-jquery-ui", "CVE-2")
	if f.FixAvailability != findings.FixAvailable {
		t.Errorf("fix availability=%q, want available (ESM entitlement observed)", f.FixAvailability)
	}
}
