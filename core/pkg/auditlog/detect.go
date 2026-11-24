package auditlog

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// hit is one detected behavioral signal before aggregation. It carries only
// identifiers and timestamps — never object content or credential material.
type hit struct {
	behavior string
	subject  string
	kind     string
	object   string
	detail   string
	ts       time.Time
}

// detector turns events into hits. It is stateless; all aggregation state
// lives in the aggregator.
type detector struct {
	cfg             Config
	sensitive       map[string]bool
	privilegedRoles map[string]bool
	execSubresource map[string]bool
}

func newDetector(cfg Config) *detector {
	return &detector{
		cfg:             cfg,
		sensitive:       cfg.sensitiveSet(),
		privilegedRoles: cfg.privilegedRoleSet(),
		execSubresource: cfg.execSubresourceSet(),
	}
}

// inspect returns all behavioral hits for one event. Events without a
// successful response status produce no hits (see Event.succeeded).
func (d *detector) inspect(ev *Event) []hit {
	if !ev.succeeded() {
		return nil
	}
	kind, subject := NormalizeSubject(ev.User.Username)
	if subject == "" {
		return nil
	}
	base := hit{subject: subject, kind: kind, ts: ev.RequestReceivedTimestamp}

	var hits []hit
	if h, ok := d.bulkSensitiveRead(ev, base); ok {
		hits = append(hits, h)
	}
	if h, ok := d.privilegedWorkload(ev, base); ok {
		hits = append(hits, h)
	}
	if hs := d.privilegedBinding(ev, base); len(hs) > 0 {
		hits = append(hits, hs...)
	}
	if h, ok := d.execIntoContainer(ev, base); ok {
		hits = append(hits, h)
	}
	if h, ok := d.anonymousAccess(ev, base); ok {
		hits = append(hits, h)
	}
	return hits
}

// bulkSensitiveRead fires when a subject reads (get/list/watch) a sensitive
// parent resource. Aggregation + thresholding happen in the aggregator.
func (d *detector) bulkSensitiveRead(ev *Event, base hit) (hit, bool) {
	if ev.ObjectRef == nil {
		return hit{}, false
	}
	verb := normalizeName(ev.Verb)
	if verb != "get" && verb != "list" && verb != "watch" {
		return hit{}, false
	}
	if !d.sensitive[ev.parentResource()] {
		return hit{}, false
	}
	base.behavior = BehaviorBulkSensitiveRead
	base.object = ev.objectID()
	base.detail = fmt.Sprintf("verb=%s resource=%s", verb, ev.parentResource())
	return base, true
}

// privilegedWorkload fires on successful creation/modification of a workload
// whose pod spec requests a privileged container or mounts a host path. Only
// the workload identifier and the kind of violation are reported.
func (d *detector) privilegedWorkload(ev *Event, base hit) (hit, bool) {
	if ev.ObjectRef == nil || len(ev.RequestObject) == 0 {
		return hit{}, false
	}
	verb := normalizeName(ev.Verb)
	if verb != "create" && verb != "update" && verb != "patch" {
		return hit{}, false
	}
	if !isWorkloadResource(ev.parentResource()) {
		return hit{}, false
	}
	privileged, hostPath := inspectPodSpecSignals(ev.RequestObject)
	if !privileged && !hostPath {
		return hit{}, false
	}
	var signals []string
	if privileged {
		signals = append(signals, "privileged-container")
	}
	if hostPath {
		signals = append(signals, "host-path-volume")
	}
	base.behavior = BehaviorPrivilegedWorkload
	base.object = ev.objectID()
	base.detail = fmt.Sprintf("verb=%s signals=%s", verb, strings.Join(signals, ","))
	return base, true
}

func isWorkloadResource(resource string) bool {
	switch resource {
	case "pods", "deployments", "daemonsets", "statefulsets", "replicasets",
		"replicationcontrollers", "jobs", "cronjobs":
		return true
	}
	return false
}

// privilegedBinding fires when a high-privilege role is bound to a normal
// (non-platform) subject. One hit per offending subject.
func (d *detector) privilegedBinding(ev *Event, base hit) []hit {
	if ev.ObjectRef == nil || len(ev.RequestObject) == 0 {
		return nil
	}
	verb := normalizeName(ev.Verb)
	if verb != "create" && verb != "update" && verb != "patch" {
		return nil
	}
	res := ev.parentResource()
	if res != "rolebindings" && res != "clusterrolebindings" {
		return nil
	}
	var body struct {
		RoleRef struct {
			Name string `json:"name"`
		} `json:"roleRef"`
		Subjects []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"subjects"`
	}
	if err := json.Unmarshal(ev.RequestObject, &body); err != nil {
		return nil
	}
	if !d.privilegedRoles[normalizeName(body.RoleRef.Name)] {
		return nil
	}
	var hits []hit
	for _, s := range body.Subjects {
		_, sid := NormalizeSubject(s.Name)
		if sid == "" || isPlatformSubject(sid, d.cfg.PlatformSubjects) {
			continue
		}
		h := base
		h.behavior = BehaviorPrivilegedBinding
		h.object = ev.objectID()
		h.detail = fmt.Sprintf("verb=%s role=%s boundSubject=%s", verb, normalizeName(body.RoleRef.Name), sid)
		hits = append(hits, h)
	}
	return hits
}

// execIntoContainer fires on successful pods/exec (or attach) access. The
// subresource is folded into the parent resource for the object identity.
func (d *detector) execIntoContainer(ev *Event, base hit) (hit, bool) {
	if ev.ObjectRef == nil {
		return hit{}, false
	}
	if ev.parentResource() != "pods" {
		return hit{}, false
	}
	if !d.execSubresource[normalizeName(ev.ObjectRef.Subresource)] {
		return hit{}, false
	}
	base.behavior = BehaviorExecIntoContainer
	base.object = ev.objectID()
	base.detail = fmt.Sprintf("subresource=%s", normalizeName(ev.ObjectRef.Subresource))
	return base, true
}

// anonymousAccess fires on any successful request by an unauthenticated
// identity.
func (d *detector) anonymousAccess(ev *Event, base hit) (hit, bool) {
	if base.subject != "system:anonymous" {
		unauthenticated := false
		for _, g := range normalizeGroups(ev.User.Groups) {
			if g == "system:unauthenticated" {
				unauthenticated = true
				break
			}
		}
		if !unauthenticated {
			return hit{}, false
		}
	}
	base.behavior = BehaviorAnonymousAccess
	base.object = ev.objectID()
	if base.object == "" {
		base.object = normalizeName(ev.Verb) + " " + "non-resource-url"
	}
	base.detail = fmt.Sprintf("verb=%s", normalizeName(ev.Verb))
	return base, true
}

// inspectPodSpecSignals walks arbitrary workload JSON looking for pod-spec
// shapes: containers/initContainers with securityContext.privileged=true and
// volumes with hostPath. It never retains object content — only two booleans
// leave this function.
func inspectPodSpecSignals(raw json.RawMessage) (privileged, hostPath bool) {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return false, false
	}
	walkForPodSignals(v, &privileged, &hostPath)
	return privileged, hostPath
}

func walkForPodSignals(v interface{}, privileged, hostPath *bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		if sc, ok := t["securityContext"].(map[string]interface{}); ok {
			if p, ok := sc["privileged"].(bool); ok && p {
				*privileged = true
			}
		}
		if hp, ok := t["hostPath"]; ok && hp != nil {
			*hostPath = true
		}
		if *privileged && *hostPath {
			return
		}
		// Stable key order keeps traversal deterministic.
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walkForPodSignals(t[k], privileged, hostPath)
			if *privileged && *hostPath {
				return
			}
		}
	case []interface{}:
		for _, item := range t {
			walkForPodSignals(item, privileged, hostPath)
			if *privileged && *hostPath {
				return
			}
		}
	}
}
