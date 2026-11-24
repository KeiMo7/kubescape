package auditlog

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// TestEndToEnd_FiveBehaviorsAndNoise builds a realistic week-of-traffic audit
// export containing all five suspicious behaviors buried in heavy noise, runs
// the analyzer over it, and asserts: every behavior is found, the noise
// produces zero findings, and merged counts / first-last timestamps are exact.
func TestEndToEnd_FiveBehaviorsAndNoise(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 3, 9, 14, 0, 0, 0, time.UTC) // Monday 14:00 UTC, inside window 14:00-14:10

	var lines [][]byte
	add := func(l []byte) { lines = append(lines, l) }

	// --- Behavior 1: bulk read of sensitive objects -------------------------
	// "alice" appears in three spellings that must normalize to one subject:
	// mixed case, fully-qualified with realm, and short name.
	aliceStart := base.Add(30 * time.Second)
	for i := 0; i < 25; i++ {
		user := []string{"Alice@Corp.LOCAL", "alice", "ALICE"}[i%3]
		add(mkEvent(t, aliceStart.Add(time.Duration(i)*time.Second), "get", user,
			[]string{"system:authenticated"}, "secrets", "", "prod", fmt.Sprintf("db-creds-%02d", i), 200, nil))
	}
	// Repeated reads of an already-seen secret: deduped out of Count.
	for i := 0; i < 5; i++ {
		add(mkEvent(t, aliceStart.Add(time.Duration(25+i)*time.Second), "get", "alice",
			nil, "secrets", "", "prod", "db-creds-00", 200, nil))
	}

	// --- Behavior 2: privileged / host-path workload ------------------------
	privPod := map[string]interface{}{
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{"name": "shell", "image": "alpine",
					"securityContext": map[string]interface{}{"privileged": true}},
			},
		},
	}
	add(mkEvent(t, base.Add(2*time.Minute), "create", "system:serviceaccount:default:deployer",
		nil, "pods", "", "prod", "debug-shell", 201, privPod))
	hostPathDeploy := map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"containers": []interface{}{map[string]interface{}{"name": "app", "image": "nginx"}},
					"volumes": []interface{}{
						map[string]interface{}{"name": "hostfs", "hostPath": map[string]interface{}{"path": "/etc"}},
					},
				},
			},
		},
	}
	add(mkEvent(t, base.Add(3*time.Minute), "create", "system:serviceaccount:default:deployer",
		nil, "deployments", "apps", "prod", "node-agent", 201, hostPathDeploy))

	// --- Behavior 3: high-privilege role bound to a normal subject ----------
	crb := map[string]interface{}{
		"roleRef": map[string]interface{}{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
		"subjects": []interface{}{
			map[string]interface{}{"kind": "User", "name": "Mallory"},
		},
	}
	add(mkEvent(t, base.Add(4*time.Minute), "create", "eve",
		nil, "clusterrolebindings", "", "", "grant-mallory-admin", 201, crb))

	// --- Behavior 4: exec into a container ----------------------------------
	execStart := base.Add(5 * time.Minute)
	for i := 0; i < 4; i++ {
		pod := []string{"api-7d9f", "api-7d9f", "worker-2", "api-7d9f"}[i]
		add(mkEvent(t, execStart.Add(time.Duration(i)*time.Second), "create", "SA:ops:debugger",
			nil, "pods", "exec", "prod", pod, 101, nil))
	}

	// --- Behavior 5: successful anonymous access -----------------------------
	anonStart := base.Add(6 * time.Minute)
	for i := 0; i < 3; i++ {
		add(mkEvent(t, anonStart.Add(time.Duration(i)*time.Second), "get", "system:anonymous",
			[]string{"system:unauthenticated"}, "configmaps", "", "kube-public", fmt.Sprintf("cm-%d", i), 200, nil))
	}
	// Anonymous attempts that failed or never completed: must NOT count.
	add(mkEvent(t, anonStart.Add(10*time.Second), "get", "system:anonymous",
		[]string{"system:unauthenticated"}, "secrets", "", "prod", "db-creds-00", 403, nil))
	add(mkEvent(t, anonStart.Add(11*time.Second), "get", "system:anonymous",
		[]string{"system:unauthenticated"}, "secrets", "", "prod", "db-creds-01", 0, nil))

	// --- Noise (must produce zero findings) ----------------------------------
	// Platform control-plane traffic.
	for i := 0; i < 800; i++ {
		add(mkEvent(t, base.Add(time.Duration(i%600)*time.Second), "list",
			"system:serviceaccount:kube-system:replicaset-controller", nil,
			"pods", "", "", "", 200, nil))
		add(mkEvent(t, base.Add(time.Duration(i%600)*time.Second), "watch",
			"system:kube-scheduler", nil, "nodes", "", "", "", 200, nil))
	}
	// Ordinary users reading non-sensitive resources.
	for i := 0; i < 500; i++ {
		add(mkEvent(t, base.Add(time.Duration(i%600)*time.Second), "get",
			fmt.Sprintf("user-%d", i%40), []string{"system:authenticated"},
			"configmaps", "", "default", fmt.Sprintf("settings-%d", i%15), 200, nil))
	}
	// Secret reads below the threshold.
	for i := 0; i < 19; i++ {
		add(mkEvent(t, base.Add(time.Duration(i)*time.Second), "get", "bob",
			nil, "secrets", "", "default", fmt.Sprintf("own-%d", i), 200, nil))
	}
	// Failed privileged-pod attempt (403): not a success.
	add(mkEvent(t, base.Add(7*time.Minute), "create", "carol", nil, "pods", "", "default", "nope", 403, privPod))
	// Binding a non-privileged role: fine.
	rbEdit := map[string]interface{}{
		"roleRef":  map[string]interface{}{"kind": "ClusterRole", "name": "edit"},
		"subjects": []interface{}{map[string]interface{}{"kind": "User", "name": "dave"}},
	}
	add(mkEvent(t, base.Add(8*time.Minute), "create", "admin", nil, "rolebindings", "", "default", "dave-edit", 201, rbEdit))
	// Binding cluster-admin to a platform subject: fine.
	crbPlatform := map[string]interface{}{
		"roleRef":  map[string]interface{}{"kind": "ClusterRole", "name": "cluster-admin"},
		"subjects": []interface{}{map[string]interface{}{"kind": "ServiceAccount", "name": "system:serviceaccount:kube-system:cluster-autoscaler"}},
	}
	add(mkEvent(t, base.Add(8*time.Minute), "create", "admin", nil, "clusterrolebindings", "", "", "autoscaler-admin", 201, crbPlatform))
	// Failed exec attempt.
	add(mkEvent(t, base.Add(9*time.Minute), "create", "mallory", nil, "pods", "exec", "prod", "api-7d9f", 403, nil))

	// --- Corruption and disorder ---------------------------------------------
	for i := 0; i < 5; i++ {
		add([]byte(fmt.Sprintf(`{"not":"an audit event", broken %d`, i)))
	}
	// Events without timestamps: counted and excluded, with a warning.
	for i := 0; i < 3; i++ {
		l := mkEvent(t, base, "get", "nouser-ts", nil, "configmaps", "", "default", fmt.Sprintf("nts-%d", i), 200, nil)
		// strip the timestamp field
		l = bytes.Replace(l, []byte(`,"requestReceivedTimestamp":`+fmt.Sprintf("%q", base.UTC().Format(time.RFC3339Nano))), nil, 1)
		add(l)
	}
	// One deliberately out-of-order event at the very end.
	add(mkEvent(t, base.Add(time.Second), "get", "late", nil, "configmaps", "", "default", "late-cm", 200, nil))

	path := writeLines(t, dir, "week.jsonl", lines)

	cfg := DefaultConfig() // default 10m window, threshold 20
	an, err := NewAnalyzer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := an.Run([]string{path})
	if err != nil {
		t.Fatal(err)
	}

	// All five behaviors detected.
	for _, b := range []string{BehaviorBulkSensitiveRead, BehaviorPrivilegedWorkload,
		BehaviorPrivilegedBinding, BehaviorExecIntoContainer, BehaviorAnonymousAccess} {
		if rep.Summary.FindingsByBehavior[b] == 0 {
			t.Errorf("behavior %q was not detected; findings: %+v", b, rep.Findings)
		}
	}

	// Noise produced zero findings: every finding subject must be one of the
	// five known offenders.
	offenders := map[string]bool{
		"alice":                                  true,
		"system:serviceaccount:default:deployer": true,
		"eve":                                    true,
		"system:serviceaccount:ops:debugger":     true,
		"system:anonymous":                       true,
	}
	for _, f := range rep.Findings {
		if !offenders[f.Subject] {
			t.Errorf("false positive on noise subject %q (%s)", f.Subject, f.Behavior)
		}
	}

	// Merged counts and first/last times for the bulk-read finding.
	var bulk *Finding
	for i := range rep.Findings {
		if rep.Findings[i].Behavior == BehaviorBulkSensitiveRead {
			bulk = &rep.Findings[i]
		}
	}
	if bulk == nil {
		t.Fatal("bulk read finding missing")
	}
	if bulk.Subject != "alice" || bulk.SubjectKind != SubjectKindUser {
		t.Errorf("subject normalization failed: %q (%s)", bulk.Subject, bulk.SubjectKind)
	}
	if bulk.Count != 25 || bulk.ObjectsTotal != 25 {
		t.Errorf("deduped count wrong: count=%d total=%d (want 25)", bulk.Count, bulk.ObjectsTotal)
	}
	if bulk.Events != 30 {
		t.Errorf("raw event count wrong: %d (want 30)", bulk.Events)
	}
	wantFirst := aliceStart.UTC().Format(time.RFC3339Nano)
	wantLast := aliceStart.Add(29 * time.Second).UTC().Format(time.RFC3339Nano)
	if bulk.FirstSeen != wantFirst || bulk.LastSeen != wantLast {
		t.Errorf("first/last wrong: %s .. %s, want %s .. %s", bulk.FirstSeen, bulk.LastSeen, wantFirst, wantLast)
	}
	if bulk.Window.Start != "2026-03-09T14:00:00Z" || bulk.Window.End != "2026-03-09T14:10:00Z" {
		t.Errorf("window wrong: %+v", bulk.Window)
	}

	// Exec finding: 2 distinct pods, 4 events, subject normalized from "SA:...".
	var exec *Finding
	for i := range rep.Findings {
		if rep.Findings[i].Behavior == BehaviorExecIntoContainer {
			exec = &rep.Findings[i]
		}
	}
	if exec == nil {
		t.Fatal("exec finding missing")
	}
	if exec.Subject != "system:serviceaccount:ops:debugger" || exec.SubjectKind != SubjectKindServiceAccount {
		t.Errorf("exec subject normalization failed: %q", exec.Subject)
	}
	if exec.Count != 2 || exec.Events != 4 {
		t.Errorf("exec dedupe wrong: count=%d events=%d (want 2/4)", exec.Count, exec.Events)
	}

	// Anonymous finding: exactly the 3 successful reads.
	var anon *Finding
	for i := range rep.Findings {
		if rep.Findings[i].Behavior == BehaviorAnonymousAccess {
			anon = &rep.Findings[i]
		}
	}
	if anon == nil {
		t.Fatal("anonymous finding missing")
	}
	if anon.Count != 3 || anon.Events != 3 {
		t.Errorf("anonymous count wrong: count=%d events=%d (want 3/3)", anon.Count, anon.Events)
	}

	// Degradation bookkeeping.
	if rep.Summary.InvalidLines != 5 {
		t.Errorf("invalid lines: got %d, want 5", rep.Summary.InvalidLines)
	}
	if rep.Summary.MissingTimestamps != 3 {
		t.Errorf("missing timestamps: got %d, want 3", rep.Summary.MissingTimestamps)
	}
	if rep.Summary.OutOfOrderEvents < 1 {
		t.Errorf("out-of-order events not detected")
	}
	if rep.Summary.Status != "complete" {
		t.Errorf("status: got %q, want complete", rep.Summary.Status)
	}
	if len(rep.Summary.Warnings) == 0 {
		t.Error("expected warnings for invalid lines / timestamps / ordering")
	}
}
