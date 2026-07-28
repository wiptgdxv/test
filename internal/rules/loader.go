package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Config is the external, code-independent fingerprint rule document.
type Config struct {
	OSHints []HintConfig `json:"os_hints"`
	Rules   []RuleConfig `json:"rules"`
}

// HintConfig maps a banner expression to a normalized operating-system hint.
type HintConfig struct {
	Pattern string `json:"pattern"`
	Value   string `json:"value"`
}

// RuleConfig describes one banner matcher.
type RuleConfig struct {
	ID           string  `json:"id"`
	Priority     int     `json:"priority"`
	Protocol     string  `json:"protocol"`
	Product      string  `json:"product"`
	Ports        []int   `json:"ports"`
	Pattern      string  `json:"pattern"`
	VersionGroup string  `json:"version_group"`
	Confidence   float64 `json:"confidence"`
	PortBonus    float64 `json:"port_bonus"`
	PortPenalty  float64 `json:"port_penalty"`
}

// Hint is a validated, compiled OS hint rule.
type Hint struct {
	Pattern *regexp.Regexp
	Value   string
}

// Rule is a validated, compiled fingerprint rule.
type Rule struct {
	ID           string
	Priority     int
	Protocol     string
	Product      string
	Ports        []int
	Pattern      *regexp.Regexp
	VersionGroup string
	Confidence   float64
	PortBonus    float64
	PortPenalty  float64
}

// Set is immutable after loading and safe to share between request goroutines.
type Set struct {
	Rules   []Rule
	OSHints []Hint
}

// LoadFile loads and validates a JSON rule file.
func LoadFile(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open rules file %q: %w", path, err)
	}
	defer f.Close()

	set, err := Load(f)
	if err != nil {
		return nil, fmt.Errorf("load rules file %q: %w", path, err)
	}
	return set, nil
}

// Load decodes, validates, and compiles a rule document.
func Load(r io.Reader) (*Set, error) {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()

	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, err
	}
	if len(cfg.Rules) == 0 {
		return nil, errors.New("rules document contains no rules")
	}

	set := &Set{
		Rules:   make([]Rule, 0, len(cfg.Rules)),
		OSHints: make([]Hint, 0, len(cfg.OSHints)),
	}

	for i, raw := range cfg.OSHints {
		if strings.TrimSpace(raw.Pattern) == "" || strings.TrimSpace(raw.Value) == "" {
			return nil, fmt.Errorf("os_hints[%d]: pattern and value are required", i)
		}
		re, err := regexp.Compile(raw.Pattern)
		if err != nil {
			return nil, fmt.Errorf("os_hints[%d]: compile pattern: %w", i, err)
		}
		set.OSHints = append(set.OSHints, Hint{Pattern: re, Value: raw.Value})
	}

	ids := make(map[string]struct{}, len(cfg.Rules))
	for i, raw := range cfg.Rules {
		if err := validateRuleConfig(i, raw, ids); err != nil {
			return nil, err
		}
		re, err := regexp.Compile(raw.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: compile pattern: %w", raw.ID, err)
		}
		if raw.VersionGroup != "" && re.SubexpIndex(raw.VersionGroup) < 0 {
			return nil, fmt.Errorf("rule %q: version group %q does not exist", raw.ID, raw.VersionGroup)
		}
		ports := append([]int(nil), raw.Ports...)
		set.Rules = append(set.Rules, Rule{
			ID:           raw.ID,
			Priority:     raw.Priority,
			Protocol:     raw.Protocol,
			Product:      raw.Product,
			Ports:        ports,
			Pattern:      re,
			VersionGroup: raw.VersionGroup,
			Confidence:   raw.Confidence,
			PortBonus:    raw.PortBonus,
			PortPenalty:  raw.PortPenalty,
		})
		ids[raw.ID] = struct{}{}
	}

	sort.SliceStable(set.Rules, func(i, j int) bool {
		if set.Rules[i].Priority != set.Rules[j].Priority {
			return set.Rules[i].Priority > set.Rules[j].Priority
		}
		if set.Rules[i].Confidence != set.Rules[j].Confidence {
			return set.Rules[i].Confidence > set.Rules[j].Confidence
		}
		return set.Rules[i].ID < set.Rules[j].ID
	})

	return set, nil
}

func validateRuleConfig(index int, rule RuleConfig, ids map[string]struct{}) error {
	prefix := fmt.Sprintf("rules[%d]", index)
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("%s: id is required", prefix)
	}
	if _, exists := ids[rule.ID]; exists {
		return fmt.Errorf("%s: duplicate id %q", prefix, rule.ID)
	}
	if strings.TrimSpace(rule.Protocol) == "" {
		return fmt.Errorf("rule %q: protocol is required", rule.ID)
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		return fmt.Errorf("rule %q: pattern is required", rule.ID)
	}
	if rule.Confidence < 0 || rule.Confidence > 1 {
		return fmt.Errorf("rule %q: confidence must be between 0 and 1", rule.ID)
	}
	if rule.PortBonus < 0 || rule.PortBonus > 1 || rule.PortPenalty < 0 || rule.PortPenalty > 1 {
		return fmt.Errorf("rule %q: port bonus and penalty must be between 0 and 1", rule.ID)
	}
	for _, port := range rule.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("rule %q: invalid port %d", rule.ID, port)
		}
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing rules data: %w", err)
	}
	return errors.New("rules document contains multiple JSON values")
}
