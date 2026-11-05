package appvuln

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
)

// Network devices (routers, switches, firewalls) are matched against what SNMP tells
// about them: a catalog entry of kind "device" names the sysObjectID, sysDescr, model and
// vendor patterns of a device operating system, where its version is and the NVD products
// whose CVEs apply. The CVEs and their version ranges come from the same vulnerability
// database, compared the same way, as those of applications.

// DeviceFormat is the format id of a device file (resolve --device).
const DeviceFormat = "openness-device/1"

// maxDeviceFile is the largest device file read; a real one is a few hundred bytes.
const maxDeviceFile = 64 << 10

// Device is one network device as the desktop read it over SNMP. It holds no host name
// and no address: a device file with any other field is refused.
type Device struct {
	Format      string `json:"format"`
	SysDescr    string `json:"sys_descr"`
	SysObjectID string `json:"sys_object_id"`
	Model       string `json:"model"`
	SoftwareRev string `json:"software_rev"`
	FirmwareRev string `json:"firmware_rev"`
	HardwareRev string `json:"hardware_rev"`
	SerialHint  string `json:"serial_hint"`
}

// IsDeviceFile says whether path is a device file (format openness-device/1). A large or
// unreadable file is not one.
func IsDeviceFile(path string) bool {
	st, err := os.Stat(path)
	if err != nil || st.Size() > maxDeviceFile {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var head struct {
		Format string `json:"format"`
	}
	return json.Unmarshal(raw, &head) == nil && head.Format == DeviceFormat
}

// ReadDeviceFile reads a device file.
func ReadDeviceFile(path string) (Device, error) {
	f, err := os.Open(path)
	if err != nil {
		return Device{}, fmt.Errorf("device: %w", err)
	}
	defer f.Close()
	dev, err := ReadDevice(f)
	if err != nil {
		return Device{}, fmt.Errorf("device %s: %w", path, err)
	}
	return dev, nil
}

// ReadDevice reads a device document. Only the openness-device/1 fields are accepted, so
// a host name or an address can not come in under another name.
func ReadDevice(r io.Reader) (Device, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxDeviceFile+1))
	if err != nil {
		return Device{}, err
	}
	if len(raw) > maxDeviceFile {
		return Device{}, fmt.Errorf("larger than %d KB; not a device file", maxDeviceFile>>10)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d Device
	if err := dec.Decode(&d); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return Device{}, fmt.Errorf("%v: only the %s fields are accepted (no host names or addresses)", err, DeviceFormat)
		}
		return Device{}, err
	}
	if d.Format != DeviceFormat {
		return Device{}, fmt.Errorf("format %q, want %q", d.Format, DeviceFormat)
	}
	return d, nil
}

// deviceMatch is one compiled match key of a device entry.
type deviceMatch struct {
	field string
	re    *regexp.Regexp
}

func (dev Device) field(name string) string {
	switch name {
	case "sys_object_id":
		return dev.SysObjectID
	case "sys_descr":
		return dev.SysDescr
	case "model":
		return dev.Model
	case "vendor":
		// The vendor is read from sysDescr: SNMP has no vendor field of its own.
		return dev.SysDescr
	case "software_rev":
		return dev.SoftwareRev
	case "firmware_rev":
		return dev.FirmwareRev
	}
	return ""
}

func (p *Product) compileDevice() error {
	for _, k := range []struct{ field, expr string }{
		{"sys_object_id", p.Match.SysObjectID}, {"sys_descr", p.Match.SysDescr},
		{"model", p.Match.Model}, {"vendor", p.Match.Vendor},
	} {
		if k.expr == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + k.expr)
		if err != nil {
			return fmt.Errorf("catalog %s: %s: %v", p.ID, k.field, err)
		}
		p.device = append(p.device, deviceMatch{k.field, re})
	}
	if len(p.device) == 0 {
		return fmt.Errorf("catalog %s: a device entry needs sys_object_id, sys_descr, model or vendor", p.ID)
	}
	switch p.Version.From {
	case "":
		p.Version.From = "sys_descr"
	case "sys_descr", "software_rev", "firmware_rev":
	default:
		return fmt.Errorf("catalog %s: version from %q, want sys_descr, software_rev or firmware_rev", p.ID, p.Version.From)
	}
	re, err := regexp.Compile(p.Version.Regex)
	if err != nil || p.Version.Regex == "" || re.NumSubexp() != 1 {
		return fmt.Errorf("catalog %s: a device version regex needs exactly one capture group (%v)", p.ID, err)
	}
	p.version = re
	return nil
}

func (p *Product) matchesDevice(dev Device) bool {
	for _, m := range p.device {
		if !m.re.MatchString(dev.field(m.field)) {
			return false
		}
	}
	return true
}

// deviceVersion reads the version the entry says where to find; "" when its regex misses.
func (p *Product) deviceVersion(dev Device) string {
	m := p.version.FindStringSubmatch(dev.field(p.Version.From))
	if len(m) < 2 {
		return ""
	}
	return p.cut(m[1])
}

// DeviceResult is what the catalog made of one device.
type DeviceResult struct {
	// Product is the matched device entry; nil when none matched.
	Product *Product
	// Skipped is an unreviewed entry that matched while those are off (Options.Unverified).
	Skipped *Product
	// Version is the device software version read by the entry; "" when it could not be read.
	Version string
	// Rules is how many CVE records the database holds for the entry's products.
	Rules        int
	Findings     []Finding
	Remediations []Remediation
}

// EvaluateDevice matches one device against the device entries of the catalog and finds
// its CVEs. The first entry whose every match key holds wins.
func (d *Data) EvaluateDevice(dev Device, opt Options) DeviceResult {
	var res DeviceResult
	for i := range d.Catalog {
		p := &d.Catalog[i]
		if !p.isDevice() || !p.matchesDevice(dev) {
			continue
		}
		if !p.Verified && !opt.Unverified {
			if res.Skipped == nil {
				res.Skipped = p
			}
			continue
		}
		res.Product = p
		break
	}
	p := res.Product
	if p == nil {
		return res
	}
	for _, c := range p.CPE {
		res.Rules += len(d.DB.Products[c])
	}
	if res.Version = p.deviceVersion(dev); res.Version == "" {
		return res
	}
	d.vulns(p, res.Version, "network_device", &res.Findings, &res.Remediations)
	return res
}

// FirstLine is the first line of a sysDescr, trimmed, with anything that looks like an IP
// address or a host name replaced by "[redacted]": the label a device is shown under.
func FirstLine(sysDescr string) string {
	line, _, _ := strings.Cut(strings.ReplaceAll(sysDescr, "\r", "\n"), "\n")
	return Redact(strings.TrimSpace(line))
}

var (
	ipLike   = regexp.MustCompile(`[0-9A-Fa-f:.]*[:.][0-9A-Fa-f:.]*`)
	hostLike = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\.[a-z]{2,}\b`)
)

// Redact replaces IP addresses and dotted host names in s with "[redacted]". Version
// numbers stay: "17.9.4a" is neither, while "10.1.2.3" is read as an address.
func Redact(s string) string {
	s = ipLike.ReplaceAllStringFunc(s, func(m string) string {
		t := strings.Trim(m, ".:")
		if strings.Count(t, ":") >= 2 || strings.Count(t, ".") == 3 {
			if net.ParseIP(t) != nil {
				return strings.Replace(m, t, "[redacted]", 1)
			}
		}
		return m
	})
	return hostLike.ReplaceAllString(s, "[redacted]")
}
