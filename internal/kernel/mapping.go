package kernel

// SignedSourceToFamily maps Ubuntu signed kernel source packages to the
// unsigned source family name used in OVAL kernel advisories. Aliases exist
// only in this table — never inferred via string prefix heuristics.
var SignedSourceToFamily = map[string]string{
	"linux-signed":                    "linux",
	"linux-signed-hwe-5.15":           "linux-hwe-5.15",
	"linux-signed-hwe-6.5":            "linux-hwe-6.5",
	"linux-signed-hwe-6.8":            "linux-hwe-6.8",
	"linux-signed-aws":                "linux-aws",
	"linux-signed-aws-6.8":            "linux-aws-6.8",
	"linux-signed-azure":              "linux-azure",
	"linux-signed-azure-6.8":          "linux-azure-6.8",
	"linux-signed-gcp":                "linux-gcp",
	"linux-signed-gcp-6.8":            "linux-gcp-6.8",
	"linux-signed-oracle":             "linux-oracle",
	"linux-signed-oracle-6.8":         "linux-oracle-6.8",
	"linux-signed-lowlatency-hwe-6.8": "linux-lowlatency-hwe-6.8",
	"linux-signed-nvidia-6.8":         "linux-nvidia-6.8",
	"linux-signed-raspi":              "linux-raspi",
	"linux-signed-kvm":                "linux-kvm",
	"linux-signed-ibm":                "linux-ibm",
	"linux-signed-gke":                "linux-gke",
	"linux-signed-fips":               "linux-fips",
	"linux-signed-oem-6.8":            "linux-oem-6.8",
}

// KnownKernelFamilies is the set of unsigned kernel source families that may
// appear on installed packages or in OVAL kernel rules.
var KnownKernelFamilies = map[string]bool{
	"linux":                    true,
	"linux-hwe-5.15":           true,
	"linux-hwe-6.5":            true,
	"linux-hwe-6.8":            true,
	"linux-aws":                true,
	"linux-aws-6.8":            true,
	"linux-azure":              true,
	"linux-azure-6.8":          true,
	"linux-gcp":                true,
	"linux-gcp-6.8":            true,
	"linux-oracle":             true,
	"linux-oracle-6.8":         true,
	"linux-lowlatency-hwe-6.8": true,
	"linux-nvidia-6.8":         true,
	"linux-raspi":              true,
	"linux-kvm":                true,
	"linux-ibm":                true,
	"linux-gke":                true,
	"linux-fips":               true,
	"linux-oem-6.8":            true,
}

// SourceFamily resolves a dpkg source package name to the unsigned kernel
// family used by Ubuntu advisories. Returns ("", false) when the mapping is
// unknown so callers can emit unknown rather than guess.
func SourceFamily(sourcePackage string) (string, bool) {
	if fam, ok := SignedSourceToFamily[sourcePackage]; ok {
		return fam, true
	}
	if KnownKernelFamilies[sourcePackage] {
		return sourcePackage, true
	}
	return "", false
}
