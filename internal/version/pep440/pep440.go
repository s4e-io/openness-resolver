// Package pep440 implements PEP 440 version comparison for PyPI distributions.
package pep440

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/s4e-io/openness-resolver/internal/version"
)

type Comparator struct{}

func init() { version.Register(Comparator{}) }

func (Comparator) Ecosystem() string { return "pep440" }

func (Comparator) Compare(installed, fixed string) (int, error) {
	return Compare(installed, fixed)
}

var epochRe = regexp.MustCompile(`^([0-9]+)!`)

type pep440Version struct {
	epoch   int
	release []int
	pre     string
	post    string
	dev     string
	local   string
	orig    string
}

func parse(v string) (pep440Version, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return pep440Version{}, fmt.Errorf("empty pep440 version")
	}
	out := pep440Version{orig: v}
	rest := v
	if m := epochRe.FindStringSubmatch(rest); len(m) == 2 {
		out.epoch, _ = strconv.Atoi(m[1])
		rest = rest[len(m[0]):]
	}
	if i := strings.Index(rest, "+"); i >= 0 {
		out.local = rest[i+1:]
		rest = rest[:i]
	}
	for _, tag := range []struct {
		prefix string
		dest   *string
	}{
		{".dev", &out.dev},
		{"a", &out.pre},
		{"b", &out.pre},
		{"rc", &out.pre},
		{".post", &out.post},
	} {
		if idx := strings.Index(rest, tag.prefix); idx >= 0 {
			if tag.prefix == "a" || tag.prefix == "b" || tag.prefix == "rc" {
				if idx > 0 && (rest[idx-1] == '.' || unicode.IsDigit(rune(rest[idx-1]))) {
					*tag.dest = rest[idx:]
					rest = rest[:idx]
					break
				}
			} else {
				*tag.dest = rest[idx:]
				rest = rest[:idx]
				break
			}
		}
	}
	parts := strings.Split(rest, ".")
	for _, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimLeftFunc(p, func(r rune) bool { return !unicode.IsDigit(r) }))
		if err != nil {
			n = 0
		}
		out.release = append(out.release, n)
	}
	return out, nil
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func cmpString(a, b string) int {
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return 1
	case b == "":
		return -1
	default:
		return strings.Compare(a, b)
	}
}

func compareParsed(a, b pep440Version) int {
	if c := cmpInt(a.epoch, b.epoch); c != 0 {
		return c
	}
	max := len(a.release)
	if len(b.release) > max {
		max = len(b.release)
	}
	for i := 0; i < max; i++ {
		av, bv := 0, 0
		if i < len(a.release) {
			av = a.release[i]
		}
		if i < len(b.release) {
			bv = b.release[i]
		}
		if c := cmpInt(av, bv); c != 0 {
			return c
		}
	}
	if c := cmpString(a.pre, b.pre); c != 0 {
		return c
	}
	if c := cmpString(a.post, b.post); c != 0 {
		return -c
	}
	if c := cmpString(a.dev, b.dev); c != 0 {
		return -c
	}
	return cmpString(a.local, b.local)
}

// Compare compares two PEP 440 version strings.
func Compare(a, b string) (int, error) {
	va, err := parse(a)
	if err != nil {
		return 0, fmt.Errorf("parse installed %q: %w", a, err)
	}
	vb, err := parse(b)
	if err != nil {
		return 0, fmt.Errorf("parse fixed %q: %w", b, err)
	}
	return compareParsed(va, vb), nil
}

// InRange reports whether version v is >= lower and < upper (empty bound open).
func InRange(v, lower, upper string) (bool, error) {
	if lower != "" {
		c, err := Compare(v, lower)
		if err != nil {
			return false, err
		}
		if c < 0 {
			return false, nil
		}
	}
	if upper != "" {
		c, err := Compare(v, upper)
		if err != nil {
			return false, err
		}
		if c >= 0 {
			return false, nil
		}
	}
	return true, nil
}
