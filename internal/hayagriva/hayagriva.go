// Package hayagriva extracts references (key, title, type, URL) from a
// Hayagriva YAML bibliography.
package hayagriva

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// Reference is one bibliography entry.
type Reference struct {
	Key   string `json:"key"`
	Type  string `json:"type,omitempty"`
	Title string `json:"title,omitempty"`
	URL   string `json:"url,omitempty"` // empty when the entry has no URL
}

// Parse reads a Hayagriva file and returns its references sorted by key, so
// the merkle leaf order does not depend on how the file is arranged.
func Parse(path string) ([]Reference, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || deref(doc.Content[0]).Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: expected a top-level mapping of citation keys to entries", path)
	}

	root := deref(doc.Content[0])

	seen := map[string]bool{}
	var refs []Reference
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i].Value
		if seen[key] {
			return nil, fmt.Errorf("%s:%d: duplicate citation key %q", path, root.Content[i].Line, key)
		}

		seen[key] = true

		ref := Reference{Key: key}
		if entry := deref(root.Content[i+1]); entry.Kind == yaml.MappingNode {
			ref.Type = text(get(entry, "type"))
			ref.Title = text(get(entry, "title"))
			ref.URL = findURL(entry, 0)
		}
		refs = append(refs, ref)

	}

	sort.SliceStable(refs, func(i, j int) bool { return refs[i].Key < refs[j].Key })
	return refs, nil
}

func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}

	return n
}

// get returns the value node for key in a mapping node, or nil.
func get(m *yaml.Node, key string) *yaml.Node {
	m = deref(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return deref(m.Content[i+1])
		}
	}

	return nil
}

// text reads a plain string, or a {value: ...} mapping (Hayagriva's
// fields-with-extras form, used by url and title).
func text(n *yaml.Node) string {
	n = deref(n)
	if n == nil {
		return ""
	}

	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value

	case yaml.MappingNode:
		return text(get(n, "value"))

	}

	return ""
}

// findURL returns the entry's own url, falling back to its parent(s), since a
// web page or article's URL is often recorded on the parent container.
func findURL(n *yaml.Node, depth int) string {
	n = deref(n)
	if n == nil || depth > 8 {
		return ""
	}

	switch n.Kind {
	case yaml.MappingNode:
		if s := text(get(n, "url")); s != "" {
			return s
		}

		return findURL(get(n, "parent"), depth+1)

	case yaml.SequenceNode:
		for _, c := range n.Content {
			if s := findURL(c, depth+1); s != "" {
				return s
			}
		}

	}

	return ""
}
