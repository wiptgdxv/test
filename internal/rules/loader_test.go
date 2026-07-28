package rules

import (
	"strings"
	"testing"
)

func TestLoadSortsAndCompilesRules(t *testing.T) {
	document := `{
  "os_hints": [{"pattern":"(?i)linux","value":"Linux"}],
  "rules": [
    {"id":"low","priority":1,"protocol":"X","product":"","ports":[],"pattern":"x","version_group":"","confidence":0.2,"port_bonus":0,"port_penalty":0},
    {"id":"high","priority":2,"protocol":"Y","product":"Y","ports":[123],"pattern":"y-(?P<version>[0-9.]+)","version_group":"version","confidence":0.8,"port_bonus":0.1,"port_penalty":0.1}
  ]
}`
	set, err := Load(strings.NewReader(document))
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(set.Rules) != 2 || set.Rules[0].ID != "high" || set.Rules[0].Pattern.SubexpIndex("version") < 1 {
		t.Fatalf("rules were not sorted/compiled: %#v", set.Rules)
	}
}

func TestLoadRejectsBrokenDocuments(t *testing.T) {
	tests := []string{
		`{"rules":[]}`,
		`{"rules":[{"id":"x","protocol":"X","pattern":"(","confidence":0.5}]}`,
		`{"rules":[{"id":"x","protocol":"X","pattern":"x","version_group":"missing","confidence":0.5}]}`,
		`{"rules":[{"id":"x","protocol":"X","pattern":"x","confidence":2}]}`,
		`{"rules":[{"id":"x","protocol":"X","pattern":"x","confidence":0.5,"unexpected":true}]}`,
	}
	for _, document := range tests {
		if _, err := Load(strings.NewReader(document)); err == nil {
			t.Fatalf("expected error for %s", document)
		}
	}
}
