package auditlog

import (
	"strings"
)

// Subject kinds after normalization.
const (
	SubjectKindUser           = "user"
	SubjectKindServiceAccount = "serviceaccount"
	SubjectKindGroup          = "group"
)

// NormalizeSubject maps a Kubernetes identity — user, service account or
// group — onto a single canonical spelling so that case differences and
// fully-qualified vs. short forms compare equal:
//
//   - leading/trailing whitespace is trimmed, everything is lower-cased;
//   - "sa:<ns>:<name>" and "system:serviceaccount:<ns>:<name>@<cluster>"
//     both become "system:serviceaccount:<ns>:<name>";
//   - a realm suffix ("alice@EXAMPLE.COM") is folded to the local name, since
//     within one cluster export the realm is constant;
//   - kind is serviceaccount for system:serviceaccount:* identities, group
//     for well-known group names, user otherwise.
func NormalizeSubject(raw string) (kind, id string) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return SubjectKindUser, ""
	}

	// Service accounts, in any accepted spelling.
	rest, ok := strings.CutPrefix(s, "system:serviceaccount:")
	if !ok {
		rest, ok = strings.CutPrefix(s, "sa:")
	}
	if ok {
		if i := strings.Index(rest, "@"); i >= 0 {
			rest = rest[:i]
		}
		return SubjectKindServiceAccount, "system:serviceaccount:" + rest
	}

	// Well-known groups.
	if s == "system:authenticated" || s == "system:unauthenticated" ||
		s == "system:masters" || s == "system:nodes" {
		return SubjectKindGroup, s
	}

	// Plain users: fold realm suffix, keep system:* identities intact.
	if i := strings.Index(s, "@"); i >= 0 && !strings.HasPrefix(s, "system:") {
		s = s[:i]
	}
	return SubjectKindUser, s
}

// normalizeGroups normalizes group memberships for comparison.
func normalizeGroups(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		_, id := NormalizeSubject(g)
		out = append(out, id)
	}
	return out
}

// isPlatformSubject reports whether a normalized subject belongs to the
// platform itself (controller-Manager, kubelet, kube-system SAs, ...) rather
// than a normal user-facing identity.
func isPlatformSubject(normalized string, platformPrefixes []string) bool {
	for _, p := range platformPrefixes {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if strings.HasPrefix(normalized, p) {
			return true
		}
	}
	return false
}
