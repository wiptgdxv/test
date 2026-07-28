package fingerprint

import (
	"math"
	"strings"

	"banner-fingerprint/internal/model"
	"banner-fingerprint/internal/rules"
)

// Engine performs deterministic, read-only rule matching and is concurrency-safe.
type Engine struct {
	rules *rules.Set
}

// NewEngine builds an engine from an already validated rule set.
func NewEngine(ruleSet *rules.Set) *Engine {
	return &Engine{rules: ruleSet}
}

// RuleCount reports how many usable rules are loaded.
func (e *Engine) RuleCount() int {
	if e == nil || e.rules == nil {
		return 0
	}
	return len(e.rules.Rules)
}

// Identify returns an unknown result instead of failing when no rule matches.
func (e *Engine) Identify(input model.ScanInput) model.Fingerprint {
	if e == nil || e.rules == nil || input.Banner == "" {
		return model.UnknownFingerprint(input)
	}

	for _, rule := range e.rules.Rules {
		matches := rule.Pattern.FindStringSubmatch(input.Banner)
		if matches == nil {
			continue
		}

		result := model.Fingerprint{
			IP:         input.IP,
			Port:       input.Port,
			Protocol:   rule.Protocol,
			Product:    rule.Product,
			Confidence: adjustedConfidence(rule, input.Port),
			OSHint:     e.detectOS(input.Banner),
		}
		if rule.VersionGroup != "" {
			index := rule.Pattern.SubexpIndex(rule.VersionGroup)
			if index > 0 && index < len(matches) {
				result.Version = cleanVersion(matches[index])
			}
		}
		return result
	}

	return model.UnknownFingerprint(input)
}

// IdentifyBatch preserves input ordering and always emits one result per input.
func (e *Engine) IdentifyBatch(inputs []model.ScanInput) []model.Fingerprint {
	results := make([]model.Fingerprint, len(inputs))
	for i := range inputs {
		results[i] = e.Identify(inputs[i])
	}
	return results
}

func (e *Engine) detectOS(banner string) string {
	for _, hint := range e.rules.OSHints {
		if hint.Pattern.MatchString(banner) {
			return hint.Value
		}
	}
	return ""
}

func adjustedConfidence(rule rules.Rule, port int) float64 {
	confidence := rule.Confidence
	if len(rule.Ports) > 0 {
		if containsPort(rule.Ports, port) {
			confidence += rule.PortBonus
		} else {
			confidence -= rule.PortPenalty
		}
	}
	confidence = math.Max(0, math.Min(1, confidence))
	return math.Round(confidence*100) / 100
}

func containsPort(ports []int, wanted int) bool {
	for _, port := range ports {
		if port == wanted {
			return true
		}
	}
	return false
}

func cleanVersion(version string) string {
	return strings.Trim(strings.TrimSpace(version), "()[]{};,\x00")
}
