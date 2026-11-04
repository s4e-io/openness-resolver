// Package apk implements Alpine APK version comparison as pure Go,
// following the token algorithm in apk-tools src/version.c.
//
// Generic SemVer is not used. The implementation is validated against
// native `apk version -t` through the fixture corpus in
// testdata/apk/corpus.txt.
package apk

import (
	"fmt"
	"strings"

	"github.com/s4e-io/openness-resolver/internal/version"
)

// Comparator implements version.VersionComparator for the apk ecosystem.
type Comparator struct{}

func init() { version.Register(Comparator{}) }

// Ecosystem returns "apk".
func (Comparator) Ecosystem() string { return "apk" }

// Compare compares two APK version strings.
func (Comparator) Compare(installed, fixed string) (int, error) {
	return Compare(installed, fixed)
}

type tokenType int

const (
	tokenInvalid     tokenType = -1
	tokenDigitOrZero tokenType = iota
	tokenDigit
	tokenLetter
	tokenSuffix
	tokenSuffixNo
	tokenRevisionNo
	tokenEnd
)

// Suffix ranks: pre-release suffixes sort before "no suffix", post
// suffixes after. Order within each group follows apk-tools.
var preSuffixes = []string{"alpha", "beta", "pre", "rc"}
var postSuffixes = []string{"cvs", "svn", "git", "hg", "p"}

func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// nextToken determines the type of the next token given the previous type,
// consuming any separator character. Direct port of apk-tools next_token().
func nextToken(prev tokenType, s string) (tokenType, string) {
	n := tokenInvalid
	switch {
	case len(s) == 0:
		n = tokenEnd
	case (prev == tokenDigit || prev == tokenDigitOrZero) && isLower(s[0]):
		n = tokenLetter
	case prev == tokenLetter && isDigit(s[0]):
		n = tokenDigit
	case prev == tokenSuffix && isDigit(s[0]):
		n = tokenSuffixNo
	default:
		switch s[0] {
		case '.':
			n = tokenDigitOrZero
		case '_':
			n = tokenSuffix
		case '-':
			if len(s) > 1 && s[1] == 'r' {
				n = tokenRevisionNo
				s = s[1:]
			} else {
				n = tokenInvalid
			}
		default:
			n = tokenInvalid
		}
		s = s[1:]
	}
	// Token type may only move forward, except for the allowed transitions.
	if n < prev {
		if !((n == tokenDigitOrZero && prev == tokenDigit) ||
			(n == tokenSuffix && prev == tokenSuffixNo) ||
			(n == tokenDigit && prev == tokenLetter)) {
			n = tokenInvalid
		}
	}
	return n, s
}

// getToken extracts the current token's ordering value and advances the
// input, mirroring apk-tools get_token():
//   - a digit component with leading zeros yields value -(zero count) and
//     the remaining digits become a separate TOKEN_DIGIT token (this gives
//     apk's fractional semantics: "1.05" < "1.5", "1.0" > "1.00");
//   - suffix words are matched by prefix in list order and rank
//     pre-release < 0 < post-release.
//
// Returns the token value, the next token type and the remaining input.
func getToken(kind tokenType, s string) (int64, tokenType, string, error) {
	if len(s) == 0 {
		return 0, tokenEnd, s, nil
	}
	switch kind {
	case tokenDigitOrZero, tokenDigit, tokenSuffixNo, tokenRevisionNo:
		if kind == tokenDigitOrZero && s[0] == '0' {
			i := 0
			for i < len(s) && s[i] == '0' {
				i++
			}
			// Remaining input continues as a DIGIT token even when empty:
			// keeping the token streams aligned matters when the other
			// version still has content ("1.0" vs "1.0_alpha").
			return int64(-i), tokenDigit, s[i:], nil
		}
		// Zero digits is tolerated (value 0), matching apk-tools: the
		// following separator is classified by nextToken. This happens
		// after a leading-zero token consumed all digits ("1.0-r0").
		i := 0
		var v int64
		for i < len(s) && isDigit(s[i]) {
			v = v*10 + int64(s[i]-'0')
			i++
		}
		next, rest := nextToken(kind, s[i:])
		return v, next, rest, nil
	case tokenLetter:
		v := int64(s[0])
		next, rest := nextToken(kind, s[1:])
		return v, next, rest, nil
	case tokenSuffix:
		for i, suf := range preSuffixes {
			if strings.HasPrefix(s, suf) {
				next, rest := nextToken(kind, s[len(suf):])
				return int64(i - len(preSuffixes)), next, rest, nil // -4..-1
			}
		}
		for i, suf := range postSuffixes {
			if strings.HasPrefix(s, suf) {
				next, rest := nextToken(kind, s[len(suf):])
				return int64(i + 1), next, rest, nil // 1..5
			}
		}
		return 0, tokenInvalid, s, fmt.Errorf("unknown suffix at %q", s)
	default:
		return 0, tokenInvalid, s, fmt.Errorf("unexpected token type %d", kind)
	}
}

// Compare compares two APK version strings and returns -1, 0 or 1.
func Compare(a, b string) (int, error) {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return 0, fmt.Errorf("empty apk version string")
	}
	// A valid APK version must start with a digit; refuse to order garbage.
	if !isDigit(a[0]) || !isDigit(b[0]) {
		return 0, fmt.Errorf("invalid apk version %q / %q: must start with a digit", a, b)
	}
	at, bt := tokenDigit, tokenDigit
	ra, rb := a, b
	for at == bt && at != tokenEnd && at != tokenInvalid {
		av, na, resta, errA := getToken(at, ra)
		bv, nb, restb, errB := getToken(bt, rb)
		if errA != nil {
			return 0, fmt.Errorf("invalid apk version %q: %v", a, errA)
		}
		if errB != nil {
			return 0, fmt.Errorf("invalid apk version %q: %v", b, errB)
		}
		if av != bv {
			if av < bv {
				return -1, nil
			}
			return 1, nil
		}
		at, bt, ra, rb = na, nb, resta, restb
	}
	if at == bt {
		// Both END (equal) or both INVALID at the same point (apk treats
		// identically-truncated streams as equal).
		return 0, nil
	}

	// Token streams diverged. A pre-release suffix makes that side smaller;
	// any other suffix falls through to token-type ordering.
	if at == tokenSuffix {
		v, _, _, err := getToken(at, ra)
		if err != nil {
			return 0, fmt.Errorf("invalid apk suffix in %q: %v", a, err)
		}
		if v < 0 {
			return -1, nil
		}
	}
	if bt == tokenSuffix {
		v, _, _, err := getToken(bt, rb)
		if err != nil {
			return 0, fmt.Errorf("invalid apk suffix in %q: %v", b, err)
		}
		if v < 0 {
			return 1, nil
		}
	}
	// Larger token-type value means that side ended earlier (END is max,
	// INVALID is min), so it is the smaller version:
	// "1.0" < "1.0.1", "1.0" < "1.0-r1", "1.0-r6" < "1.0-r6_p1",
	// "1.0_p2" < "1.0a1" (SUFFIX > LETTER).
	if at > bt {
		return -1, nil
	}
	return 1, nil
}

func sign(c int) int {
	switch {
	case c < 0:
		return -1
	case c > 0:
		return 1
	default:
		return 0
	}
}
