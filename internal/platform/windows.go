package platform

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/evidence"
)

// WindowsProduct is the resolved MSRC product identity of a Windows host.
type WindowsProduct struct {
	// Key matches the lowercase CPE product MSRC uses (windows_server_2022,
	// windows_11_24h2). Empty when the build could not be mapped.
	Key string
	// Build is "<build>.<ubr>" as installed, the winbuild comparator input.
	Build string
	// Server reports whether the host was classified as a server SKU.
	Server bool
	Reason string
}

// windowsBuilds maps a build number to the MSRC product keys for server and
// client SKUs. Server 2025 and Windows 11 24H2 share build 26100 but are
// serviced in different UBR streams, so the SKU decides the key.
//
// Every entry is taken from the MSRC CVRF feed itself (January 2023 to
// October 2026): the key is the lowercase CPE product and the build is the
// one carried by the large majority of that product's FixedBuild values.
// Products whose fixed builds cannot pin a host build (windows_server_1903,
// 1909, 2004, 20h2: no FixedBuild since 2023) or that are not a host OS
// (hlk, adk, driver kit) are deliberately absent.
var windowsBuilds = map[string]struct{ server, client string }{
	"28000": {"", "windows_11_26h1"},
	"26200": {"", "windows_11_25h2"},
	"26100": {"windows_server_2025", "windows_11_24h2"},
	"25398": {"windows_server_23h2", ""},
	"22631": {"", "windows_11_23h2"},
	"22621": {"", "windows_11_22h2"},
	"22000": {"", "windows_11_21h2"},
	"20348": {"windows_server_2022", ""},
	"19045": {"", "windows_10_22h2"},
	"19044": {"", "windows_10_21h2"},
	"19043": {"", "windows_10_21h1"},
	"19042": {"", "windows_10_20h2"},
	"17763": {"windows_server_2019", "windows_10_1809"},
	"14393": {"windows_server_2016", "windows_10_1607"},
	"10240": {"", "windows_10_1507"},
	"9600":  {"windows_server_2012_r2", ""},
	"9200":  {"windows_server_2012", ""},
	"7601":  {"windows_server_2008_r2", ""},
	"6003":  {"windows_server_2008_sp2", ""},
}

// windowsUnserviced explains builds that MSRC still lists but whose last
// fixes predate the feed window by years. Mapping them would make a host
// that stopped receiving updates look clean, so they stay unmapped with an
// explicit reason.
var windowsUnserviced = map[string]struct{ server, client string }{
	"7601": {"", "Windows 7 (build 7601) received its last MSRC fixes in January 2023; current vulnerabilities are not published for it"},
	"9600": {"", "Windows 8.1 (build 9600) received its last MSRC fixes in January 2023; current vulnerabilities are not published for it"},
}

// ResolveWindowsProduct maps collector Windows OS identity (build_number,
// ubr, product_type / installation_type) onto an MSRC product key. Nothing
// is guessed: a build outside the table or a missing UBR yields an empty Key
// with a reason.
func ResolveWindowsProduct(os evidence.OperatingSystem) WindowsProduct {
	build := strings.TrimSpace(os.BuildNumber.String())
	ubr := strings.TrimSpace(os.UBR.String())
	if build == "" || ubr == "" {
		// os_build "26100.33650" is the collector's convenience field.
		if parts := strings.Split(strings.TrimSpace(os.OSBuild), "."); len(parts) == 2 {
			build, ubr = parts[0], parts[1]
		}
	}
	wp := WindowsProduct{Server: windowsIsServer(os)}
	if build == "" {
		wp.Reason = "windows build_number missing from evidence"
		return wp
	}
	if ubr == "" {
		wp.Reason = "windows UBR missing from evidence; build " + build + " cannot be compared"
		return wp
	}
	if n, err := strconv.Atoi(build); err != nil || n <= 0 {
		wp.Reason = fmt.Sprintf("windows build_number %q is not a positive number", build)
		return wp
	}
	if n, err := strconv.Atoi(ubr); err != nil || n < 0 {
		wp.Reason = fmt.Sprintf("windows UBR %q is not a number; build %s cannot be compared", ubr, build)
		return wp
	}
	wp.Build = build + "." + ubr
	entry, ok := windowsBuilds[build]
	if !ok {
		wp.Reason = fmt.Sprintf("windows build %s is not in the MSRC product map", build)
		return wp
	}
	if wp.Server {
		wp.Key = entry.server
	} else {
		wp.Key = entry.client
	}
	if wp.Key == "" {
		if u, ok := windowsUnserviced[build]; ok {
			reason := u.client
			if wp.Server {
				reason = u.server
			}
			if reason != "" {
				wp.Reason = reason
				return wp
			}
		}
		sku := "client"
		if wp.Server {
			sku = "server"
		}
		wp.Reason = fmt.Sprintf("windows build %s has no %s product in the MSRC product map", build, sku)
	}
	return wp
}

// windowsIsServer decides the SKU from product_type (Win32_OperatingSystem:
// 1 workstation, 2 domain controller, 3 server), then installation_type,
// then the product name.
func windowsIsServer(os evidence.OperatingSystem) bool {
	switch strings.TrimSpace(os.ProductType.String()) {
	case "1":
		return false
	case "2", "3":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.InstallationType)) {
	case "server", "server core", "nano server":
		return true
	case "client":
		return false
	}
	return strings.Contains(strings.ToLower(os.ProductName), "server")
}
