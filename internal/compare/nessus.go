// Package compare cross-checks the resolver's findings against a third-party
// scanner report (Nessus .nessus XML) at the CVE level. It is validation
// tooling: it makes no vulnerability decisions, it only diffs two decided
// sets and explains where they disagree.
package compare

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// NessusReport is the subset of the .nessus (NessusClientData_v2) schema we
// need: per-host report items, each of which may reference several CVEs.
type NessusReport struct {
	XMLName xml.Name         `xml:"NessusClientData_v2"`
	Report  nessusReportNode `xml:"Report"`
}

type nessusReportNode struct {
	Name  string       `xml:"name,attr"`
	Hosts []nessusHost `xml:"ReportHost"`
}

type nessusHost struct {
	Name  string           `xml:"name,attr"`
	Items []nessusItem     `xml:"ReportItem"`
	Props []nessusHostProp `xml:"HostProperties>tag"`
}

type nessusHostProp struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusItem struct {
	PluginID     string   `xml:"pluginID,attr"`
	PluginName   string   `xml:"pluginName,attr"`
	PluginFamily string   `xml:"pluginFamily,attr"`
	Severity     int      `xml:"severity,attr"`
	Port         string   `xml:"port,attr"`
	RiskFactor   string   `xml:"risk_factor"`
	CVEs         []string `xml:"cve"`
}

// NessusCVE is one CVE as reported by Nessus, with the strongest severity and
// the plugins that referenced it.
type NessusCVE struct {
	CVE         string   `json:"cve"`
	MaxSeverity int      `json:"max_severity"` // 0 info .. 4 critical
	Plugins     []string `json:"plugins"`
	// LocalCheck is true when at least one referencing plugin is a
	// distribution local security check (credentialed, package-level).
	LocalCheck bool `json:"local_check"`
}

// NessusResult is the parsed, host-scoped view of a Nessus report.
type NessusResult struct {
	Host string                `json:"host"`
	CVEs map[string]*NessusCVE `json:"-"`
	// LocalChecksPresent reports whether any credentialed local security
	// check plugin ran; without it, a package-level comparison is invalid.
	LocalChecksPresent bool `json:"local_checks_present"`
	// OSInfo is the Nessus-detected operating system, if present.
	OSInfo string `json:"os_info,omitempty"`
}

func severityToInt(risk string) int {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// localCheckFamilies are Nessus plugin families that indicate credentialed,
// package-level checks (the only class comparable to our OVAL-based rules).
var localCheckFamilies = map[string]bool{
	"Ubuntu Local Security Checks": true,
	"Debian Local Security Checks": true,
}

// ParseNessusFile reads a .nessus report and returns the CVE view for the
// requested host. If host is "" and exactly one host is present, that host
// is used; otherwise the host name must match.
func ParseNessusFile(path, host string) (*NessusResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseNessus(f, host)
}

// ParseNessus parses a .nessus document from r.
func ParseNessus(r io.Reader, host string) (*NessusResult, error) {
	var rep NessusReport
	if err := xml.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("parse nessus xml: %w", err)
	}
	if len(rep.Report.Hosts) == 0 {
		return nil, fmt.Errorf("nessus report contains no hosts")
	}
	var hn *nessusHost
	switch {
	case host != "":
		for i := range rep.Report.Hosts {
			if rep.Report.Hosts[i].Name == host {
				hn = &rep.Report.Hosts[i]
				break
			}
		}
		if hn == nil {
			names := make([]string, 0, len(rep.Report.Hosts))
			for _, h := range rep.Report.Hosts {
				names = append(names, h.Name)
			}
			return nil, fmt.Errorf("host %q not found in report; available: %s", host, strings.Join(names, ", "))
		}
	case len(rep.Report.Hosts) == 1:
		hn = &rep.Report.Hosts[0]
	default:
		names := make([]string, 0, len(rep.Report.Hosts))
		for _, h := range rep.Report.Hosts {
			names = append(names, h.Name)
		}
		return nil, fmt.Errorf("report has %d hosts; pass --host (available: %s)", len(rep.Report.Hosts), strings.Join(names, ", "))
	}

	res := &NessusResult{Host: hn.Name, CVEs: map[string]*NessusCVE{}}
	for _, p := range hn.Props {
		if p.Name == "operating-system" {
			res.OSInfo = p.Value
		}
	}
	for _, it := range hn.Items {
		local := localCheckFamilies[it.PluginFamily]
		if local {
			res.LocalChecksPresent = true
		}
		sev := it.Severity
		if s := severityToInt(it.RiskFactor); s > sev {
			sev = s
		}
		for _, raw := range it.CVEs {
			cve := strings.ToUpper(strings.TrimSpace(raw))
			if cve == "" {
				continue
			}
			c := res.CVEs[cve]
			if c == nil {
				c = &NessusCVE{CVE: cve}
				res.CVEs[cve] = c
			}
			if sev > c.MaxSeverity {
				c.MaxSeverity = sev
			}
			if local {
				c.LocalCheck = true
			}
			if it.PluginName != "" && !containsStr(c.Plugins, it.PluginName) {
				c.Plugins = append(c.Plugins, it.PluginName)
			}
		}
	}
	return res, nil
}

// CVESet returns the sorted set of CVE IDs. When localOnly is true, only CVEs
// referenced by a credentialed local security check are returned.
func (n *NessusResult) CVESet(localOnly bool) []string {
	var out []string
	for cve, c := range n.CVEs {
		if localOnly && !c.LocalCheck {
			continue
		}
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
