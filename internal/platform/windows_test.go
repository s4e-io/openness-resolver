package platform

import (
	"encoding/json"
	"testing"

	"github.com/s4e-io/openness-resolver/internal/evidence"
)

func osFromJSON(t *testing.T, s string) evidence.OperatingSystem {
	t.Helper()
	var os evidence.OperatingSystem
	if err := json.Unmarshal([]byte(s), &os); err != nil {
		t.Fatal(err)
	}
	return os
}

func TestResolveWindowsProduct(t *testing.T) {
	cases := []struct {
		name, js, key, build string
	}{
		{"server 2025 numeric ubr", `{"distribution_id":"windows","product_name":"Microsoft Windows Server 2025 Datacenter","build_number":"26100","ubr":33650,"product_type":3,"installation_type":"Server"}`, "windows_server_2025", "26100.33650"},
		{"win11 24h2 same build", `{"distribution_id":"windows","product_name":"Windows 11 Pro","build_number":"26100","ubr":"9711","product_type":1}`, "windows_11_24h2", "26100.9711"},
		{"server 2022 by installation_type", `{"distribution_id":"windows","product_name":"x","build_number":"20348","ubr":"5761","installation_type":"Server Core"}`, "windows_server_2022", "20348.5761"},
		{"os_build fallback", `{"distribution_id":"windows","product_name":"Windows 10 Enterprise","os_build":"19045.7807"}`, "windows_10_22h2", "19045.7807"},
		{"unknown build", `{"distribution_id":"windows","build_number":"12345","ubr":"1","product_type":1}`, "", "12345.1"},
		{"missing ubr", `{"distribution_id":"windows","build_number":"20348","product_type":3}`, "", ""},
		{"negative ubr is not comparable", `{"distribution_id":"windows","build_number":"20348","ubr":"-5","product_type":3}`, "", ""},
		{"garbage ubr", `{"distribution_id":"windows","build_number":"20348","ubr":"x1","product_type":3}`, "", ""},
		{"garbage build", `{"distribution_id":"windows","build_number":"20348a","ubr":"1","product_type":3}`, "", ""},
		{"client build on server sku", `{"distribution_id":"windows","build_number":"22631","ubr":"4","product_type":3}`, "", "22631.4"},
		{"win11 26h1", `{"distribution_id":"windows","product_name":"Microsoft Windows 11 Pro","build_number":"28000","ubr":2525,"product_type":1,"installation_type":"Client"}`, "windows_11_26h1", "28000.2525"},
		{"server 23h2 core", `{"distribution_id":"windows","product_name":"Microsoft Windows Server Datacenter","build_number":"25398","ubr":1160,"product_type":3,"installation_type":"Server Core"}`, "windows_server_23h2", "25398.1160"},
		{"domain controller", `{"distribution_id":"windows","product_name":"Microsoft Windows Server 2022 Standard","build_number":"20348","ubr":5000,"product_type":2,"installation_type":"Server"}`, "windows_server_2022", "20348.5000"},
		{"server 2008 r2", `{"distribution_id":"windows","product_name":"Microsoft Windows Server 2008 R2 Standard","build_number":"7601","ubr":27000,"product_type":3}`, "windows_server_2008_r2", "7601.27000"},
		{"server 2008 sp2", `{"distribution_id":"windows","product_name":"Microsoft Windows Server 2008 Standard","build_number":"6003","ubr":22000,"product_type":3}`, "windows_server_2008_sp2", "6003.22000"},
		{"windows 7 is unserviced", `{"distribution_id":"windows","product_name":"Microsoft Windows 7 Professional","build_number":"7601","ubr":26000,"product_type":1}`, "", "7601.26000"},
		{"windows 8.1 is unserviced", `{"distribution_id":"windows","product_name":"Microsoft Windows 8.1 Pro","build_number":"9600","ubr":21000,"product_type":1}`, "", "9600.21000"},
	}
	for _, tc := range cases {
		wp := ResolveWindowsProduct(osFromJSON(t, tc.js))
		if wp.Key != tc.key || wp.Build != tc.build {
			t.Errorf("%s: got key=%q build=%q reason=%q", tc.name, wp.Key, wp.Build, wp.Reason)
		}
		if wp.Key == "" && wp.Reason == "" {
			t.Errorf("%s: empty key needs a reason", tc.name)
		}
	}
}

func TestFromOSWindows(t *testing.T) {
	os := osFromJSON(t, `{"distribution_id":"windows","distribution_name":"Windows","product_name":"Microsoft Windows Server 2022 Datacenter","version_id":"21H2","architecture":"amd64","build_number":"20348","ubr":"5000","product_type":3}`)
	ctx := FromOS(os, evidence.Kernel{})
	if ctx.DistributionID != "windows" || ctx.Codename != "windows_server_2022" || ctx.CodenameSource != "windows_product" {
		t.Fatalf("%+v", ctx)
	}
	if ctx.WindowsBuild != "20348.5000" || ctx.Architecture != "amd64" {
		t.Fatalf("%+v", ctx)
	}
	if st, _ := ctx.Support(); st != Supported {
		t.Fatalf("support %s", st)
	}
	unmapped := FromOS(osFromJSON(t, `{"distribution_id":"windows","build_number":"1","ubr":"1"}`), evidence.Kernel{})
	if st, reason := unmapped.Support(); st != NotSupported || reason == "" {
		t.Fatalf("unmapped build must be not_supported with reason: %s %q", st, reason)
	}
}
