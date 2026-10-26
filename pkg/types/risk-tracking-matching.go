package types

import (
	"fmt"
	"sort"
	"strings"
)

// Risk tracking declarations use the same @-delimited risk id syntax as the generated
// risks (risk-category@affected-element@...). A declaration segment is either a literal
// segment, which must match one @-delimited part exactly, or a single "*" wildcard
// segment, which matches any one @-delimited part.
//
// The declarations as written by the user stay untouched in Model.RiskTracking, while
// ResolveRiskTracking derives the effective per-risk tracking (exact declarations plus
// winning wildcard expansions) into Model.effectiveRiskTracking.

const wildcardSegment = "*"

func normalizeRiskTrackingId(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

type riskTrackingDeclaration struct {
	key           string // trimmed declaration key as written by the user
	normalizedKey string
	tracking      *RiskTracking
	segments      []string
	wildcard      bool
	wildcardCount int
}

func parseRiskTrackingDeclaration(key string, tracking *RiskTracking) (*riskTrackingDeclaration, error) {
	trimmed := strings.TrimSpace(key)
	normalized := normalizeRiskTrackingId(trimmed)
	if !strings.Contains(normalized, "@") {
		return nil, fmt.Errorf("invalid risk tracking declaration %q: risk ids are @-delimited (like \"risk-category@affected-element\") and the wildcard * must match a whole @-delimited segment", key)
	}
	segments := strings.Split(normalized, "@")
	wildcardCount := 0
	for _, segment := range segments {
		if segment == "" {
			return nil, fmt.Errorf("invalid risk tracking declaration %q: empty @-delimited segment", key)
		}
		if strings.Contains(segment, "*") {
			if segment != wildcardSegment {
				return nil, fmt.Errorf("invalid risk tracking declaration %q: the wildcard * must match a whole @-delimited segment", key)
			}
			wildcardCount++
		}
	}
	return &riskTrackingDeclaration{
		key:           trimmed,
		normalizedKey: normalized,
		tracking:      tracking,
		segments:      segments,
		wildcard:      wildcardCount > 0,
		wildcardCount: wildcardCount,
	}, nil
}

// matchesRiskId performs anchored segment-wise matching: the segment count and every
// literal segment must match. Substring matches (e.g. "cat@vault" matching
// "cat@vault-server") and segment-count mismatches (e.g. "cat@*" matching "cat@a@b")
// are therefore impossible.
func (declaration *riskTrackingDeclaration) matchesRiskId(riskIdSegments []string) bool {
	if len(declaration.segments) != len(riskIdSegments) {
		return false
	}
	for index, segment := range declaration.segments {
		if segment != wildcardSegment && segment != riskIdSegments[index] {
			return false
		}
	}
	return true
}

// ResolveRiskTracking separates the declared risk tracking (exact risk ids and wildcard
// patterns kept verbatim in Model.RiskTracking) from the effective per-risk tracking.
//
// Resolution rules are independent of map iteration order:
//   - An exact declaration always wins over any wildcard pattern for the same risk.
//   - Among overlapping wildcard patterns the one with fewer wildcard segments (more
//     specific) wins deterministically.
//   - Equally specific wildcard patterns matching the same risk are reported as a
//     conflict, since the result would otherwise depend on declaration order.
//   - Declarations matching no generated risk are orphans and are either logged (when
//     ignoreOrphanedRiskTracking is set) or returned as an error.
//
// The result is stored as derived state only: RiskTracking is never modified, so the
// resolution can run any number of times with identical results and both the risk
// reports and the model macros share the same resolved view.
func (model *Model) ResolveRiskTracking(ignoreOrphanedRiskTracking bool, progressReporter ProgressReporter) error {
	progressReporter.Info("Resolving risk tracking declarations")

	declarations := make([]*riskTrackingDeclaration, 0, len(model.RiskTracking))
	declarationsByNormalizedKey := make(map[string]*riskTrackingDeclaration)
	for key, tracking := range model.RiskTracking {
		declaration, err := parseRiskTrackingDeclaration(key, tracking)
		if err != nil {
			return err
		}
		if existing, duplicate := declarationsByNormalizedKey[declaration.normalizedKey]; duplicate {
			return fmt.Errorf("duplicate risk tracking declaration: %q and %q resolve to the same risk id pattern", existing.key, declaration.key)
		}
		declarationsByNormalizedKey[declaration.normalizedKey] = declaration
		declarations = append(declarations, declaration)
	}
	sort.Slice(declarations, func(i, j int) bool {
		return declarations[i].normalizedKey < declarations[j].normalizedKey
	})

	exactDeclarations := make(map[string]*riskTrackingDeclaration)
	wildcardDeclarations := make([]*riskTrackingDeclaration, 0)
	for _, declaration := range declarations {
		if declaration.wildcard {
			wildcardDeclarations = append(wildcardDeclarations, declaration)
		} else {
			exactDeclarations[declaration.normalizedKey] = declaration
		}
	}
	// Deterministic specificity order: fewer wildcard segments first (more specific
	// wins), lexical pattern order as a stable tie-break for processing and logging.
	sort.SliceStable(wildcardDeclarations, func(i, j int) bool {
		if wildcardDeclarations[i].wildcardCount != wildcardDeclarations[j].wildcardCount {
			return wildcardDeclarations[i].wildcardCount < wildcardDeclarations[j].wildcardCount
		}
		return wildcardDeclarations[i].normalizedKey < wildcardDeclarations[j].normalizedKey
	})

	generatedRiskIds := make([]string, 0, len(model.GeneratedRisksBySyntheticId))
	for riskId := range model.GeneratedRisksBySyntheticId {
		generatedRiskIds = append(generatedRiskIds, riskId)
	}
	sort.Strings(generatedRiskIds)

	effectiveRiskTracking := make(map[string]*RiskTracking)
	matchedWildcardDeclarations := make(map[*riskTrackingDeclaration]bool)
	for _, riskId := range generatedRiskIds {
		riskIdSegments := strings.Split(riskId, "@")
		if exactDeclaration, exists := exactDeclarations[riskId]; exists {
			// Exact declarations always take priority over wildcard patterns.
			effectiveRiskTracking[riskId] = exactDeclaration.tracking
			continue
		}
		winningDeclarations := make([]*riskTrackingDeclaration, 0)
		bestWildcardCount := -1
		for _, declaration := range wildcardDeclarations {
			if !declaration.matchesRiskId(riskIdSegments) {
				continue
			}
			matchedWildcardDeclarations[declaration] = true
			if bestWildcardCount == -1 || declaration.wildcardCount < bestWildcardCount {
				bestWildcardCount = declaration.wildcardCount
				winningDeclarations = []*riskTrackingDeclaration{declaration}
			} else if declaration.wildcardCount == bestWildcardCount {
				winningDeclarations = append(winningDeclarations, declaration)
			}
		}
		if len(winningDeclarations) == 0 {
			continue
		}
		if len(winningDeclarations) > 1 {
			conflictingPatterns := make([]string, len(winningDeclarations))
			for index, winner := range winningDeclarations {
				conflictingPatterns[index] = winner.key
			}
			sort.Strings(conflictingPatterns)
			return fmt.Errorf("ambiguous risk tracking for risk id %q: the equally specific wildcard patterns %s all match; "+
				"declare the risk id exactly or make one of the patterns more specific",
				riskId, strings.Join(conflictingPatterns, ", "))
		}
		winner := winningDeclarations[0]
		effectiveRiskTracking[riskId] = expandRiskTracking(winner.tracking, riskId)
		progressReporter.Infof("Applying wildcard risk tracking %q to risk id: %v", winner.key, riskId)
	}

	progressReporter.Info("Checking risk tracking")
	for _, declaration := range declarations {
		orphaned := false
		if declaration.wildcard {
			orphaned = !matchedWildcardDeclarations[declaration]
		} else {
			_, orphaned = model.GeneratedRisksBySyntheticId[declaration.normalizedKey]
			orphaned = !orphaned
		}
		if !orphaned {
			continue
		}
		if ignoreOrphanedRiskTracking {
			if declaration.wildcard {
				progressReporter.Warnf("Wildcard risk tracking does not match any risk id: %v", declaration.key)
			} else {
				progressReporter.Infof("Risk tracking references unknown risk (risk id not found): %v", declaration.key)
			}
			continue
		}
		if declaration.wildcard {
			return fmt.Errorf("wildcard risk tracking does not match any risk id: %v", declaration.key)
		}
		return fmt.Errorf("Risk tracking references unknown risk (risk id not found) - you might want to use the option -ignore-orphaned-risk-tracking: %v"+
			"\n\nNOTE: For risk tracking each risk-id needs to be defined (the string with the @ sign in it). "+
			"These unique risk IDs are visible in the PDF report (the small grey string under each risk), "+
			"the Excel (column \"ID\"), as well as the JSON responses. Some risk IDs have only one @ sign in them, "+
			"while others multiple. The idea is to allow for unique but still speaking IDs. Therefore each risk instance "+
			"creates its individual ID by taking all affected elements causing the risk to be within an @-delimited part. "+
			"Using wildcards (the * sign) for parts delimited by @ signs allows to handle groups of certain risks at once. "+
			"Best is to lookup the IDs to use in the created Excel file. Alternatively a model macro \"seed-risk-tracking\" "+
			"is available that helps in initially seeding the risk tracking part here based on already identified and not yet handled risks",
			declaration.key)
	}

	model.effectiveRiskTracking = effectiveRiskTracking
	return nil
}

// expandRiskTracking creates the effective tracking entry for a concrete risk id based
// on a wildcard declaration. The declaration entry is copied so that declarations and
// their shared tracking details stay untouched.
func expandRiskTracking(declaration *RiskTracking, riskId string) *RiskTracking {
	return &RiskTracking{
		SyntheticRiskId: riskId,
		Justification:   declaration.Justification,
		Ticket:          declaration.Ticket,
		CheckedBy:       declaration.CheckedBy,
		Status:          declaration.Status,
		Date:            declaration.Date,
	}
}

// getEffectiveRiskTracking returns the resolved tracking for a concrete risk id. When
// the model went through ResolveRiskTracking the shared resolved view is used
// (exact declarations plus winning wildcard expansions). Otherwise only exact
// declarations are considered as a fallback for directly constructed models.
func (model *Model) getEffectiveRiskTracking(syntheticRiskId string) *RiskTracking {
	normalizedRiskId := normalizeRiskTrackingId(syntheticRiskId)
	if model.effectiveRiskTracking != nil {
		return model.effectiveRiskTracking[normalizedRiskId]
	}
	for declaredRiskId, tracking := range model.RiskTracking {
		if normalizeRiskTrackingId(declaredRiskId) == normalizedRiskId {
			return tracking
		}
	}
	return nil
}
