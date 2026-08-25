package upgrade

import (
	"strconv"
	"strings"
)

// Semver is a parsed semantic-version triple with an optional pre-release
// suffix. Build metadata ("+foo") is accepted on input and ignored.
type Semver struct {
	Major, Minor, Patch uint64
	Pre                 string // text after "-", empty when absent
}

// ParseVersion parses release-style version strings: "v1.2.3", "1.2",
// "1.2.3-rc.1", "v1.2.3-3-gabcdef-dirty". It rejects anything whose dotted
// components are not fully numeric — in particular "", "dev" and bare commit
// hashes like "7c2859c" — so callers can tell a release build from a
// development build.
func ParseVersion(s string) (Semver, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Semver{}, false
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	// Build metadata never affects ordering; drop it first.
	if i := strings.Index(s, "+"); i >= 0 {
		s = s[:i]
	}
	var pre string
	if i := strings.Index(s, "-"); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return Semver{}, false
	}
	var nums [3]uint64
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return Semver{}, false
		}
		nums[i] = n
	}
	return Semver{Major: nums[0], Minor: nums[1], Patch: nums[2], Pre: pre}, true
}

// CompareVersion returns -1, 0 or 1 for a vs b. Numeric triples compare
// first; a pre-release suffix sorts OLDER than the same version without one,
// and two pre-release strings compare byte-wise. That is enough for the only
// decision this package makes — "latest tag vs my version" — and is not a
// full semver implementation.
func CompareVersion(a, b Semver) int {
	switch {
	case a.Major != b.Major:
		return cmpUint(a.Major, b.Major)
	case a.Minor != b.Minor:
		return cmpUint(a.Minor, b.Minor)
	case a.Patch != b.Patch:
		return cmpUint(a.Patch, b.Patch)
	}
	switch {
	case a.Pre == "" && b.Pre == "":
		return 0
	case a.Pre == "":
		return 1 // release beats pre-release
	case b.Pre == "":
		return -1
	default:
		return strings.Compare(a.Pre, b.Pre)
	}
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
