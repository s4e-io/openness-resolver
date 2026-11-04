package resolver

import (
	"testing"

	"github.com/s4e-io/openness-resolver/internal/findings"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"

	_ "github.com/s4e-io/openness-resolver/internal/version/apk"
	_ "github.com/s4e-io/openness-resolver/internal/version/dpkg"
)

func TestBinaryFixedVersionNotSharedAcrossSiblings(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("libreoffice-base-core", "1:7.3.7-0ubuntu0.22.04.12", tf.WithSource("libreoffice"))

	rBase := tf.UbuntuRule("CVE-2022-3140", "jammy", "libreoffice", "libreoffice-base-core", rules.StatusReleased, "1:7.3.6-0ubuntu0.22.04.2")
	rFonts := tf.UbuntuRule("CVE-2022-3140", "jammy", "libreoffice", "fonts-opensymbol", rules.StatusReleased, "2:102.12+LibO7.3.6-0ubuntu0.22.04.2")
	rFonts.RuleID += ":fonts"

	res := resolve(t, doc, rBase, rFonts)
	f := mustFinding(t, res, "libreoffice-base-core", "CVE-2022-3140")
	if f.State != findings.StateFixed {
		t.Fatalf("state=%s want fixed (installed >= binary-specific fixed version)", f.State)
	}
	if f.FixedVersion != "1:7.3.6-0ubuntu0.22.04.2" {
		t.Fatalf("fixed=%q want libreoffice-base-core note version", f.FixedVersion)
	}
	if f.Rule == nil || f.Rule.RuleID != rBase.RuleID {
		t.Fatalf("rule=%v want %s", f.Rule, rBase.RuleID)
	}
}

func TestUtilLinuxSiblingBinaryUsesOwnFixedVersion(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("bsdextrautils", "2.37.2-4ubuntu3.5", tf.WithSource("util-linux"))

	rExtra := tf.UbuntuRule("CVE-2024-28085", "jammy", "util-linux", "bsdextrautils", rules.StatusReleased, "2.37.2-4ubuntu3.4")
	rUtils := tf.UbuntuRule("CVE-2024-28085", "jammy", "util-linux", "bsdutils", rules.StatusReleased, "1:2.37.2-4ubuntu3.4")
	rUtils.RuleID += ":bsdutils"

	res := resolve(t, doc, rExtra, rUtils)
	f := mustFinding(t, res, "bsdextrautils", "CVE-2024-28085")
	if f.State != findings.StateFixed {
		t.Fatalf("state=%s want fixed", f.State)
	}
	if f.FixedVersion != "2.37.2-4ubuntu3.4" {
		t.Fatalf("fixed=%q want bsdextrautils-specific version without bsdutils epoch", f.FixedVersion)
	}
}

func TestMultipleUSNsSameBinaryStillSupersede(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().AddPackage("libssl3", "3.0.2-0ubuntu1.17", tf.WithSource("openssl"))
	r1 := tf.UbuntuRule("CVE-11", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.16")
	r2 := tf.UbuntuRule("CVE-11", "jammy", "openssl", "libssl3", rules.StatusReleased, "3.0.2-0ubuntu1.19")
	r2.RuleID += ":newer"
	res := resolve(t, doc, r1, r2)
	f := mustFinding(t, res, "libssl3", "CVE-11")
	if f.FixedVersion != "3.0.2-0ubuntu1.19" {
		t.Fatalf("fixed=%s want newest USN for same binary", f.FixedVersion)
	}
}
