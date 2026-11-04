package resolver_test

import (
	"encoding/json"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/resolver"
	"github.com/s4e-io/openness-resolver/internal/rules"
	tf "github.com/s4e-io/openness-resolver/internal/testfixtures"
)

func TestSoftwareInventoryPassThroughAndUnknowns(t *testing.T) {
	doc := tf.NewUbuntuJammyARM64().
		AddPackage("openssl", "3.0.2-0ubuntu1.18", tf.WithSource("openssl")).
		AddSoftwareInstance(map[string]any{
			"entity_id": "sw:nginx:host:abc", "product_key": "nginx", "vendor": "f5", "product": "nginx",
			"cpe_prefix": "cpe:2.3:a:f5:nginx", "scope": "host", "install_path": "/usr",
			"version": "1.24.0", "version_source": map[string]any{"source": "file_regex", "path": "/usr/sbin/nginx", "value": "1.24.0"},
			"version_candidates": []any{}, "patch_ids": []any{}, "confidence": "direct", "gap": nil, "running": true,
			"signals":          map[string]any{"paths": []any{"/usr/sbin/nginx"}, "processes": []any{}, "ports": []any{80}, "registry": []any{}},
			"catalog_verified": true,
		}).
		AddSoftwareInstance(map[string]any{
			"entity_id": "sw:oracle-database:host:def", "product_key": "oracle-database", "vendor": "oracle", "product": "database_server",
			"scope": "host", "install_path": "/u01/app/oracle/product/19.0.0/dbhome_1",
			"version": nil, "version_source": nil, "version_candidates": []any{}, "patch_ids": []any{"36233263"},
			"confidence": "presence_only", "gap": "version_unreadable", "running": false,
			"signals":          map[string]any{"paths": []any{}, "processes": []any{}, "ports": []any{}, "registry": []any{}},
			"catalog_verified": false,
		}).
		AddSoftwareInstance(map[string]any{
			"entity_type": "software_inventory_summary", "entity_id": "swinv:summary", "catalog_version": "2026.10.1",
		})
	lr, err := doc.Load()
	if err != nil {
		t.Fatal(err)
	}
	rs := &rules.RuleSet{Rules: []rules.PackageVulnerabilityRule{
		tf.UbuntuRule("CVE-2024-0001", "jammy", "openssl", "openssl", rules.StatusReleased, "3.0.2-0ubuntu1.19"),
	}}
	res, err := resolver.NewEngine(rs).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	if res.OutputSchemaVersion != "2" {
		t.Fatalf("output schema %s", res.OutputSchemaVersion)
	}
	if res.Asset.Hostname != "t" || res.Asset.Platform != "linux" || res.Asset.CollectorVersion != "test" {
		t.Fatalf("asset summary %+v", res.Asset)
	}
	if len(res.SoftwareInventory) != 2 {
		t.Fatalf("software instances %d (summary row must be skipped)", len(res.SoftwareInventory))
	}
	nginx, oracle := res.SoftwareInventory[0], res.SoftwareInventory[1]
	if nginx.ProductKey != "nginx" || nginx.Version != "1.24.0" || !nginx.Running || nginx.Ports[0] != 80 {
		t.Fatalf("nginx %+v", nginx)
	}
	if nginx.Resolution.Status != resolver.SoftwareNoRules {
		t.Fatalf("nginx resolution %+v", nginx.Resolution)
	}
	if oracle.Resolution.Status != resolver.SoftwareVersionUnreadable || oracle.CatalogVerified {
		t.Fatalf("oracle resolution %+v", oracle.Resolution)
	}
	if len(oracle.Resolution.Reasons) < 2 || oracle.PatchIDs[0] != "36233263" {
		t.Fatalf("oracle reasons %+v patches %v", oracle.Resolution.Reasons, oracle.PatchIDs)
	}

	kinds := map[string]int{}
	for _, u := range res.Unknowns {
		kinds[u.Kind]++
	}
	if kinds["software"] != 2 {
		t.Fatalf("software unknowns %v", kinds)
	}
	if kinds["platform"] != 0 || kinds["rule_coverage"] != 0 {
		t.Fatalf("jammy with rules must not be unknown: %v", kinds)
	}

	// JSON contract: lists are never null.
	b, _ := json.Marshal(res)
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"software_inventory", "unknowns", "remediation_groups", "findings"} {
		if _, isList := m[k].([]any); !isList {
			t.Fatalf("%s must be a JSON array, got %T", k, m[k])
		}
	}
}

func TestUnknownsOnEvidenceWithoutSoftwareInventory(t *testing.T) {
	lr, err := tf.NewUbuntuJammyARM64().AddPackage("bash", "5.1-6ubuntu1", tf.WithSource("bash")).Load()
	if err != nil {
		t.Fatal(err)
	}
	res, err := resolver.NewEngine(&rules.RuleSet{}).Resolve(lr)
	if err != nil {
		t.Fatal(err)
	}
	if res.SoftwareInventory == nil || len(res.SoftwareInventory) != 0 {
		t.Fatalf("expected empty list, got %v", res.SoftwareInventory)
	}
	found := false
	for _, u := range res.Unknowns {
		if u.Kind == "rule_coverage" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no rules for jammy must surface as a rule_coverage unknown: %+v", res.Unknowns)
	}
}
