package auditlog

import (
	"fmt"
	"os"
	"time"

	"sigs.k8s.io/yaml"
)

// Behavior identifiers emitted in findings. These double as SARIF rule IDs.
const (
	BehaviorBulkSensitiveRead  = "bulk-sensitive-read"
	BehaviorPrivilegedWorkload = "privileged-workload"
	BehaviorPrivilegedBinding  = "privileged-role-binding"
	BehaviorExecIntoContainer  = "exec-into-container"
	BehaviorAnonymousAccess    = "anonymous-access"
)

// Default configuration values. Every threshold has an explicit default so the
// analyzer works with zero configuration.
const (
	DefaultWindowSeconds        = 600 // 10 minutes
	DefaultBulkReadThreshold    = 20
	DefaultMaxObjectsPerFinding = 100
)

// Config controls detection thresholds and output shaping. It can be loaded
// from a YAML/JSON file and/or overridden by CLI flags. Validate must be
// called before analysis; any illegal value is a startup error.
type Config struct {
	// WindowSeconds is the tumbling aggregation window, aligned to the Unix
	// epoch. Same subject + same behavior inside one window merges into a
	// single finding.
	WindowSeconds int64 `json:"windowSeconds" yaml:"windowSeconds"`

	// BulkReadThreshold is the number of distinct sensitive objects a subject
	// must successfully read inside one window to raise a finding.
	BulkReadThreshold int `json:"bulkReadThreshold" yaml:"bulkReadThreshold"`

	// SensitiveResources are the parent resources (plural, lowercase) treated
	// as sensitive for bulk-read detection. Subresources are folded into the
	// parent before matching.
	SensitiveResources []string `json:"sensitiveResources" yaml:"sensitiveResources"`

	// PrivilegedRoles are roleRef names (case-insensitive) considered
	// high-privilege when bound to a normal subject.
	PrivilegedRoles []string `json:"privilegedRoles" yaml:"privilegedRoles"`

	// PlatformSubjects are normalized subject prefixes considered platform
	// identities; bindings targeting them are not "normal subjects".
	PlatformSubjects []string `json:"platformSubjects" yaml:"platformSubjects"`

	// ExecSubresources are pod subresources treated as "entering a container".
	ExecSubresources []string `json:"execSubresources" yaml:"execSubresources"`

	// MaxObjectsPerFinding caps how many object identifiers are embedded in a
	// finding; the full distinct count is always reported.
	MaxObjectsPerFinding int `json:"maxObjectsPerFinding" yaml:"maxObjectsPerFinding"`
}

// DefaultConfig returns the built-in configuration.
func DefaultConfig() Config {
	return Config{
		WindowSeconds:      DefaultWindowSeconds,
		BulkReadThreshold:  DefaultBulkReadThreshold,
		SensitiveResources: []string{"secrets"},
		PrivilegedRoles:    []string{"cluster-admin"},
		PlatformSubjects: []string{
			"system:masters",
			"system:apiserver",
			"system:kube-",
			"system:node",
			"system:serviceaccount:kube-system:",
		},
		ExecSubresources:     []string{"exec", "attach"},
		MaxObjectsPerFinding: DefaultMaxObjectsPerFinding,
	}
}

// LoadConfig reads a YAML or JSON config file. An empty path returns the
// default configuration.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		return cfg, cfg.Validate()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading audit config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing audit config %q: %w", path, err)
	}
	return cfg, cfg.Validate()
}

// Validate rejects illegal configuration. It is called at startup, before any
// input file is opened, so a bad config fails fast.
func (c *Config) Validate() error {
	if c.WindowSeconds <= 0 {
		return fmt.Errorf("windowSeconds must be > 0, got %d", c.WindowSeconds)
	}
	if c.BulkReadThreshold < 1 {
		return fmt.Errorf("bulkReadThreshold must be >= 1, got %d", c.BulkReadThreshold)
	}
	if c.MaxObjectsPerFinding < 0 {
		return fmt.Errorf("maxObjectsPerFinding must be >= 0, got %d", c.MaxObjectsPerFinding)
	}
	if len(c.SensitiveResources) == 0 {
		return fmt.Errorf("sensitiveResources must not be empty")
	}
	if len(c.PrivilegedRoles) == 0 {
		return fmt.Errorf("privilegedRoles must not be empty")
	}
	if len(c.ExecSubresources) == 0 {
		return fmt.Errorf("execSubresources must not be empty")
	}
	return nil
}

// window returns the tumbling window containing t.
func (c Config) windowOf(t time.Time) Window {
	idx := t.Unix() / c.WindowSeconds
	start := time.Unix(idx*c.WindowSeconds, 0).UTC()
	end := time.Unix((idx+1)*c.WindowSeconds, 0).UTC()
	return Window{Start: start, End: end}
}

func (c Config) sensitiveSet() map[string]bool {
	m := make(map[string]bool, len(c.SensitiveResources))
	for _, r := range c.SensitiveResources {
		m[normalizeResource(r)] = true
	}
	return m
}

func (c Config) privilegedRoleSet() map[string]bool {
	m := make(map[string]bool, len(c.PrivilegedRoles))
	for _, r := range c.PrivilegedRoles {
		m[normalizeName(r)] = true
	}
	return m
}

func (c Config) execSubresourceSet() map[string]bool {
	m := make(map[string]bool, len(c.ExecSubresources))
	for _, s := range c.ExecSubresources {
		m[normalizeName(s)] = true
	}
	return m
}
