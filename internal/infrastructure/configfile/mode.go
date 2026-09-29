package configfile

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lib4u/vnm/internal/domain/policy"
)

// WithMode returns the policy file with the mode at key — "mode", or
// "guard", "mode" — replaced and everything else — comments, blank lines,
// order — byte for byte as the operator wrote it: only the value token
// changes. The result is parsed back, so a file this returns is always one the
// agent accepts.
func WithMode(data []byte, key []string, mode policy.Mode) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", policy.ErrInvalid, err)
	}
	value, err := scalarAt(&doc, key)
	if err != nil {
		return nil, err
	}

	lines := bytes.SplitAfter(data, []byte("\n"))
	if value.Line < 1 || value.Line > len(lines) {
		return nil, fmt.Errorf("mode at line %d is outside the file", value.Line)
	}
	line := lines[value.Line-1]
	token, err := plainToken(value)
	if err != nil {
		return nil, err
	}
	// yaml.v3 counts columns in characters, not bytes.
	runes := []rune(string(line))
	if value.Column < 1 || value.Column-1 > len(runes) {
		return nil, fmt.Errorf("mode at line %d column %d is outside the line", value.Line, value.Column)
	}
	start := len(string(runes[:value.Column-1]))
	end := start + len(token)
	if end > len(line) || string(line[start:end]) != token {
		return nil, fmt.Errorf("%s at line %d is not written as %s; write it so", strings.Join(key, "."), value.Line, token)
	}
	edited := append(append(append([]byte{}, line[:start]...), mode.String()...), line[end:]...)
	lines[value.Line-1] = edited
	out := bytes.Join(lines, nil)

	if _, err := Parse(out); err != nil {
		return nil, fmt.Errorf("the edited policy is invalid: %w", err)
	}
	var check yaml.Node
	if err := yaml.Unmarshal(out, &check); err != nil {
		return nil, err
	}
	if got, err := scalarAt(&check, key); err != nil || got.Value != mode.String() {
		return nil, fmt.Errorf("the edited policy does not read %s = %s", strings.Join(key, "."), mode)
	}
	return out, nil
}

// scalarAt finds the scalar value at a path of mapping keys.
func scalarAt(doc *yaml.Node, key []string) (*yaml.Node, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, fmt.Errorf("%w: the policy is not a single document", policy.ErrInvalid)
	}
	node := doc.Content[0]
	for depth, k := range key {
		if node.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%w: %s is not a mapping", policy.ErrInvalid, strings.Join(key[:depth], "."))
		}
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == k {
				next = node.Content[i+1]
			}
		}
		if next == nil {
			// Adding a key would mean re-encoding the file; the shipped
			// config has every mode written out.
			return nil, fmt.Errorf("the policy has no %s key; add it to the file first", strings.Join(key[:depth+1], "."))
		}
		node = next
	}
	if node.Kind != yaml.ScalarNode {
		return nil, fmt.Errorf("%w: %s is not a scalar", policy.ErrInvalid, strings.Join(key, "."))
	}
	return node, nil
}

// Format is the policy file format, for the use cases that edit the file.
type Format struct{}

// Parse decodes and validates a policy.
func (Format) Parse(data []byte) (policy.Config, error) { return Parse(data) }

// WithMode returns the file with the mode at key replaced.
func (Format) WithMode(data []byte, key []string, mode policy.Mode) ([]byte, error) {
	return WithMode(data, key, mode)
}

// plainToken is how the value must be written for a byte-exact edit: bare or
// in plain quotes. An anchor, a tag or an escape moves the value's bytes away
// from what the parser reports; such a file is left for the operator to edit.
func plainToken(v *yaml.Node) (string, error) {
	if v.Anchor != "" || (v.Tag != "" && v.Tag != "!!str") {
		return "", fmt.Errorf("the mode at line %d carries an anchor or a tag; write it as a plain value", v.Line)
	}
	switch {
	case v.Style&yaml.DoubleQuotedStyle != 0:
		return `"` + v.Value + `"`, nil
	case v.Style&yaml.SingleQuotedStyle != 0:
		return "'" + v.Value + "'", nil
	default:
		return v.Value, nil
	}
}
