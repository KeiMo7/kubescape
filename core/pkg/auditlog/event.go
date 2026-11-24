package auditlog

import (
	"encoding/json"
	"strings"
	"time"
)

// Event is the subset of a Kubernetes audit.k8s.io/v1 Event needed for
// behavioral detection. requestObject is kept as raw JSON and only inspected
// for privilege signals; its contents are never copied into the report.
type Event struct {
	Verb string `json:"verb"`
	User struct {
		Username string   `json:"username"`
		Groups   []string `json:"groups"`
	} `json:"user"`
	ObjectRef *struct {
		Resource    string `json:"resource"`
		Subresource string `json:"subresource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		APIGroup    string `json:"apiGroup"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code int32 `json:"code"`
	} `json:"responseStatus"`
	RequestReceivedTimestamp time.Time       `json:"requestReceivedTimestamp"`
	RequestObject            json.RawMessage `json:"requestObject"`
}

// parseEvent decodes one audit event line. It returns an error for malformed
// JSON so the caller can count and skip the line without aborting the batch.
func parseEvent(line []byte) (*Event, error) {
	var ev Event
	if err := json.Unmarshal(line, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

// succeeded reports whether the event represents a completed, successful
// API call: a 2xx response, or 101 (Switching Protocols) which is the success
// response for upgraded connections such as exec/attach. An event without a
// response status — the request never completed or the audit policy did not
// record the response — is never counted as a success.
func (e *Event) succeeded() bool {
	if e.ResponseStatus == nil {
		return false
	}
	code := e.ResponseStatus.Code
	return code == 101 || (code >= 200 && code < 300)
}

// parentResource folds a subresource access back into its parent resource so
// one object never yields two identities (pods/exec -> pods).
func (e *Event) parentResource() string {
	if e.ObjectRef == nil {
		return ""
	}
	return normalizeResource(e.ObjectRef.Resource)
}

// objectID is the stable, content-free identifier of the accessed object:
// apiGroup/parent-resource/namespace/name. Subresources never appear here.
func (e *Event) objectID() string {
	if e.ObjectRef == nil {
		return ""
	}
	parts := []string{}
	if g := normalizeName(e.ObjectRef.APIGroup); g != "" {
		parts = append(parts, g)
	}
	parts = append(parts, normalizeResource(e.ObjectRef.Resource))
	if ns := e.ObjectRef.Namespace; ns != "" {
		parts = append(parts, ns)
	}
	name := e.ObjectRef.Name
	if name == "" {
		name = "*" // collection-level access (list/watch)
	}
	parts = append(parts, name)
	return strings.Join(parts, "/")
}

func normalizeResource(r string) string {
	return strings.ToLower(strings.TrimSpace(r))
}

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
