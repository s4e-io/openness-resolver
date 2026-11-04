package evidence

import (
	"encoding/json"
	"testing"
)

func TestPackageValueHighestList(t *testing.T) {
	raw := []byte(`{
		"name":"openssl","raw_version_string":"3.0.2-1",
		"highest_list_version":"3.0.2-2",
		"highest_list_origin":{"origin":"Ubuntu","url":"http://archive.ubuntu.com/ubuntu","esm":false}
	}`)
	var v PackageValue
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.HighestListVersion != "3.0.2-2" || v.HighestListOrigin == nil || v.HighestListOrigin.Origin != "Ubuntu" {
		t.Fatalf("%+v", v)
	}
}

func TestPackageValueLegacyCandidateAlias(t *testing.T) {
	raw := []byte(`{
		"name":"openssl","raw_version_string":"3.0.2-1",
		"candidate_version":"3.0.2-9",
		"candidate_origin":"UbuntuESMApps"
	}`)
	var v PackageValue
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.HighestListVersion != "3.0.2-9" {
		t.Fatalf("version=%q", v.HighestListVersion)
	}
	if v.HighestListOrigin == nil || v.HighestListOrigin.Origin != "UbuntuESMApps" {
		t.Fatalf("origin=%+v", v.HighestListOrigin)
	}
}
