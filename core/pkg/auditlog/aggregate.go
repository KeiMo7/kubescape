package auditlog

import (
	"sort"
	"time"
)

// aggregateKey identifies one merged finding: same subject, same behavior,
// same window.
type aggregateKey struct {
	behavior string
	subject  string
	window   int64 // window start, unix seconds
}

// accumulator merges hits for one key. The object set deduplicates repeated
// access to the same object inside the window, so Count reflects distinct
// objects touched, not raw event volume.
type accumulator struct {
	kind      string
	detail    string
	window    Window
	first     time.Time
	last      time.Time
	objects   map[string]struct{}
	hitEvents int64
}

// aggregator holds one accumulator per (subject, behavior, window). Memory is
// proportional to the number of distinct keys and distinct objects per key —
// not to input size.
type aggregator struct {
	cfg  Config
	accs map[aggregateKey]*accumulator
}

func newAggregator(cfg Config) *aggregator {
	return &aggregator{cfg: cfg, accs: make(map[aggregateKey]*accumulator)}
}

func (a *aggregator) add(h hit) {
	w := a.cfg.windowOf(h.ts)
	key := aggregateKey{behavior: h.behavior, subject: h.subject, window: w.Start.Unix()}
	acc, ok := a.accs[key]
	if !ok {
		acc = &accumulator{
			kind:    h.kind,
			detail:  h.detail,
			window:  w,
			first:   h.ts,
			last:    h.ts,
			objects: make(map[string]struct{}),
		}
		a.accs[key] = acc
	}
	acc.hitEvents++
	if h.ts.Before(acc.first) {
		acc.first = h.ts
	}
	if h.ts.After(acc.last) {
		acc.last = h.ts
	}
	if h.object != "" {
		acc.objects[h.object] = struct{}{}
	}
	if h.detail != "" {
		acc.detail = h.detail
	}
}

// findings materializes the merged findings. Bulk-read findings are emitted
// only once the distinct-object count reaches the configured threshold; all
// other behaviors emit one finding per key. Output is sorted deterministically.
func (a *aggregator) findings() []Finding {
	out := make([]Finding, 0, len(a.accs))
	for key, acc := range a.accs {
		count := len(acc.objects)
		if count == 0 {
			count = int(acc.hitEvents)
		}
		if key.behavior == BehaviorBulkSensitiveRead && count < a.cfg.BulkReadThreshold {
			continue
		}
		objects := make([]string, 0, len(acc.objects))
		for o := range acc.objects {
			objects = append(objects, o)
		}
		sort.Strings(objects)
		truncated := false
		if a.cfg.MaxObjectsPerFinding >= 0 && len(objects) > a.cfg.MaxObjectsPerFinding {
			objects = objects[:a.cfg.MaxObjectsPerFinding]
			truncated = true
		}
		out = append(out, Finding{
			Behavior:         key.behavior,
			Subject:          key.subject,
			SubjectKind:      acc.kind,
			Window:           acc.window.json(),
			Count:            count,
			Events:           acc.hitEvents,
			FirstSeen:        acc.first.UTC().Format(time.RFC3339Nano),
			LastSeen:         acc.last.UTC().Format(time.RFC3339Nano),
			Detail:           acc.detail,
			Objects:          objects,
			ObjectsTotal:     len(acc.objects),
			ObjectsTruncated: truncated,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		if a.Behavior != b.Behavior {
			return a.Behavior < b.Behavior
		}
		if a.Window.Start != b.Window.Start {
			return a.Window.Start < b.Window.Start
		}
		return a.Detail < b.Detail
	})
	return out
}
