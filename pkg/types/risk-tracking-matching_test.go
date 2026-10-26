package types

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type recordingProgressReporter struct {
	infos  []string
	warns  []string
	errors []string
}

func (r *recordingProgressReporter) Info(a ...any)  { r.infos = append(r.infos, fmt.Sprint(a...)) }
func (r *recordingProgressReporter) Warn(a ...any)  { r.warns = append(r.warns, fmt.Sprint(a...)) }
func (r *recordingProgressReporter) Error(a ...any) { r.errors = append(r.errors, fmt.Sprint(a...)) }
func (r *recordingProgressReporter) Infof(f string, a ...any) {
	r.infos = append(r.infos, fmt.Sprintf(f, a...))
}
func (r *recordingProgressReporter) Warnf(f string, a ...any) {
	r.warns = append(r.warns, fmt.Sprintf(f, a...))
}
func (r *recordingProgressReporter) Errorf(f string, a ...any) {
	r.errors = append(r.errors, fmt.Sprintf(f, a...))
}

func riskTrackingDeclarationForTest(status RiskStatus) *RiskTracking {
	return &RiskTracking{Status: status, Justification: status.String()}
}

func newRiskTrackingTestModel(declarations map[string]*RiskTracking, riskIds ...string) *Model {
	model := &Model{
		RiskTracking:                declarations,
		GeneratedRisksBySyntheticId: make(map[string]*Risk),
	}
	for _, riskId := range riskIds {
		normalized := normalizeRiskTrackingId(riskId)
		model.GeneratedRisksBySyntheticId[normalized] = &Risk{SyntheticId: riskId}
	}
	return model
}

func TestParseRiskTrackingDeclaration(t *testing.T) {
	declaration, err := parseRiskTrackingDeclaration(" Cat@*@webshop ", riskTrackingDeclarationForTest(Accepted))
	assert.NoError(t, err)
	assert.Equal(t, "Cat@*@webshop", declaration.key)
	assert.Equal(t, "cat@*@webshop", declaration.normalizedKey)
	assert.True(t, declaration.wildcard)
	assert.Equal(t, 1, declaration.wildcardCount)
	assert.Equal(t, []string{"cat", "*", "webshop"}, declaration.segments)

	exact, err := parseRiskTrackingDeclaration("cat@webshop", riskTrackingDeclarationForTest(Accepted))
	assert.NoError(t, err)
	assert.False(t, exact.wildcard)
	assert.Equal(t, 0, exact.wildcardCount)

	for _, invalid := range []string{"no-at-sign", "cat@", "@asset", "cat@a*", "cat@*@", "cat@a*b@c"} {
		_, err := parseRiskTrackingDeclaration(invalid, riskTrackingDeclarationForTest(Accepted))
		assert.Error(t, err, invalid)
	}
}

func TestRiskTrackingDeclarationMatchesBySegments(t *testing.T) {
	cases := []struct {
		pattern string
		riskId  string
		match   bool
	}{
		{"cat@asset", "cat@asset", true},
		{"cat@asset", "cat@asset-server", false}, // no substring matching of @-delimited segments
		{"cat@asset", "cat@asset@flow", false},   // anchored segment count
		{"cat@asset", "xcat@asset", false},
		{"cat@asset", "dog@asset", false},
		{"cat@*", "cat@asset", true},
		{"cat@*", "cat@a@b", false}, // "*" matches exactly one segment, not zero or many
		{"cat@*@*", "cat@a@b", true},
		{"cat@*@*", "cat@a", false},
		{"cat@a@*", "cat@a@b", true},
		{"cat@a@*", "cat@x@b", false},
		{"cat@*@b", "cat@a@b", true},
		{"cat@*@b", "cat@a@c", false},
		{"ldap-injection@*@ldap-auth-server@*", "ldap-injection@caller@ldap-auth-server@flow", true},
	}
	for _, testCase := range cases {
		declaration, err := parseRiskTrackingDeclaration(testCase.pattern, nil)
		assert.NoError(t, err)
		actual := declaration.matchesRiskId(strings.Split(normalizeRiskTrackingId(testCase.riskId), "@"))
		assert.Equal(t, testCase.match, actual, "%q vs %q", testCase.pattern, testCase.riskId)
	}
}

func TestResolveRiskTrackingExactDeclarationWinsOverWildcard(t *testing.T) {
	declarations := map[string]*RiskTracking{
		"cat@a": {Status: Accepted, Justification: "exact"},
		"cat@*": {Status: Mitigated, Justification: "wildcard"},
	}
	model := newRiskTrackingTestModel(declarations, "cat@a", "cat@b")

	assert.NoError(t, model.ResolveRiskTracking(false, &recordingProgressReporter{}))

	riskA := model.GeneratedRisksBySyntheticId["cat@a"]
	riskB := model.GeneratedRisksBySyntheticId["cat@b"]
	assert.Equal(t, Accepted, model.GetRiskTracking(riskA).Status)
	assert.Equal(t, "exact", model.GetRiskTracking(riskA).Justification)
	assert.Equal(t, Mitigated, model.GetRiskTracking(riskB).Status)
	assert.True(t, model.IsRiskTracked(riskA))
	assert.True(t, model.IsRiskTracked(riskB))

	// the wildcard expansion is a copy keyed by the concrete risk id and never aliases
	// the declaration it came from
	expanded := model.effectiveRiskTracking["cat@b"]
	assert.Equal(t, "cat@b", expanded.SyntheticRiskId)
	assert.Equal(t, "wildcard", expanded.Justification)
	assert.NotSame(t, model.RiskTracking["cat@*"], expanded)

	// declarations stay as written by the user: no expansions written back
	assert.Len(t, model.RiskTracking, 2)
	assert.Contains(t, model.RiskTracking, "cat@*")
	assert.NotContains(t, model.RiskTracking, "cat@b")
}

func TestResolveRiskTrackingMoreSpecificPatternWinsStably(t *testing.T) {
	// Map iteration order is randomized in Go, so repeat the resolution to prove the
	// outcome never depends on declaration traversal order.
	for iteration := 0; iteration < 20; iteration++ {
		declarations := map[string]*RiskTracking{
			"cat@*@*": {Status: Accepted, Justification: "broad"},
			"cat@a@*": {Status: Mitigated, Justification: "specific"},
		}
		model := newRiskTrackingTestModel(declarations, "cat@a@b", "cat@x@y")

		assert.NoError(t, model.ResolveRiskTracking(false, &recordingProgressReporter{}))

		assert.Equal(t, Mitigated, model.effectiveRiskTracking["cat@a@b"].Status)
		assert.Equal(t, "specific", model.effectiveRiskTracking["cat@a@b"].Justification)
		assert.Equal(t, Accepted, model.effectiveRiskTracking["cat@x@y"].Status)
		assert.Equal(t, "broad", model.effectiveRiskTracking["cat@x@y"].Justification)
	}
}

func TestResolveRiskTrackingEqualSpecificityOverlapIsConflict(t *testing.T) {
	cases := []struct {
		name     string
		statuses []RiskStatus // statuses of "cat@a@*" and "cat@*@b"
	}{
		{"different tracking payloads", []RiskStatus{Mitigated, Accepted}},
		{"identical tracking payloads are still ambiguous", []RiskStatus{Accepted, Accepted}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			declarations := map[string]*RiskTracking{
				"cat@a@*": {Status: testCase.statuses[0]},
				"cat@*@b": {Status: testCase.statuses[1]},
			}
			model := newRiskTrackingTestModel(declarations, "cat@a@b", "cat@a@z")

			err := model.ResolveRiskTracking(false, &recordingProgressReporter{})
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "cat@a@b")
			assert.Contains(t, err.Error(), "cat@a@*")
			assert.Contains(t, err.Error(), "cat@*@b")
		})
	}
}

func TestResolveRiskTrackingIsIdempotentAndKeepsDeclarations(t *testing.T) {
	declarations := map[string]*RiskTracking{
		"cat@*@*": {Status: Accepted},
		"cat@a@*": {Status: Mitigated},
		"dog@x":   {Status: FalsePositive},
	}
	model := newRiskTrackingTestModel(declarations, "cat@a@b", "cat@z@y", "dog@x")
	reporter := &recordingProgressReporter{}

	assert.NoError(t, model.ResolveRiskTracking(false, reporter))
	firstRun := make(map[string]RiskStatus, len(model.effectiveRiskTracking))
	for riskId, tracking := range model.effectiveRiskTracking {
		firstRun[riskId] = tracking.Status
	}

	// analyzing the same model again must not change anything
	assert.NoError(t, model.ResolveRiskTracking(false, reporter))
	assert.Len(t, model.effectiveRiskTracking, len(firstRun))
	for riskId, status := range firstRun {
		assert.Equal(t, status, model.effectiveRiskTracking[riskId].Status, riskId)
	}
	assert.Len(t, model.RiskTracking, 3)
	assert.Contains(t, model.RiskTracking, "cat@*@*")
	assert.Contains(t, model.RiskTracking, "cat@a@*")
	assert.Contains(t, model.RiskTracking, "dog@x")
	assert.NotContains(t, model.RiskTracking, "cat@a@b")
	assert.NotContains(t, model.RiskTracking, "cat@z@y")
}

func TestResolveRiskTrackingExactSubstringIsTrueOrphan(t *testing.T) {
	model := newRiskTrackingTestModel(
		map[string]*RiskTracking{"cat@vault": riskTrackingDeclarationForTest(Accepted)},
		"cat@vault-server", // looks similar, but is a different @-delimited risk id
	)

	err := model.ResolveRiskTracking(false, &recordingProgressReporter{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown risk")
	assert.Nil(t, model.effectiveRiskTracking)

	reporter := &recordingProgressReporter{}
	model = newRiskTrackingTestModel(
		map[string]*RiskTracking{"cat@vault": riskTrackingDeclarationForTest(Accepted)},
		"cat@vault-server",
	)
	assert.NoError(t, model.ResolveRiskTracking(true, reporter))
	assert.Len(t, model.effectiveRiskTracking, 0)
	assert.False(t, model.IsRiskTracked(model.GeneratedRisksBySyntheticId["cat@vault-server"]))
	assert.Contains(t, strings.Join(reporter.infos, "\n"), "cat@vault")
}

func TestResolveRiskTrackingWildcardSegmentCountMismatchIsOrphan(t *testing.T) {
	model := newRiskTrackingTestModel(
		map[string]*RiskTracking{"cat@*": riskTrackingDeclarationForTest(Mitigated)},
		"cat@a@b", // "*" only matches a single segment
	)

	err := model.ResolveRiskTracking(false, &recordingProgressReporter{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wildcard risk tracking does not match any risk id")

	reporter := &recordingProgressReporter{}
	model = newRiskTrackingTestModel(
		map[string]*RiskTracking{"cat@*": riskTrackingDeclarationForTest(Mitigated)},
		"cat@a@b",
	)
	assert.NoError(t, model.ResolveRiskTracking(true, reporter))
	assert.Contains(t, strings.Join(reporter.warns, "\n"), "cat@*")
	assert.Len(t, model.effectiveRiskTracking, 0)
}

func TestResolveRiskTrackingWildcardWithoutAnyMatchIsOrphan(t *testing.T) {
	model := newRiskTrackingTestModel(
		map[string]*RiskTracking{"cat@*": riskTrackingDeclarationForTest(Mitigated)},
		"dog@x",
	)
	err := model.ResolveRiskTracking(false, &recordingProgressReporter{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cat@*")

	reporter := &recordingProgressReporter{}
	model = newRiskTrackingTestModel(
		map[string]*RiskTracking{"cat@*": riskTrackingDeclarationForTest(Mitigated)},
		"dog@x",
	)
	assert.NoError(t, model.ResolveRiskTracking(true, reporter))
	assert.Contains(t, strings.Join(reporter.warns, "\n"), "cat@*")
}

func TestResolveRiskTrackingInvalidPattern(t *testing.T) {
	model := newRiskTrackingTestModel(
		map[string]*RiskTracking{"cat@web*": riskTrackingDeclarationForTest(Accepted)},
		"cat@webshop",
	)
	err := model.ResolveRiskTracking(false, &recordingProgressReporter{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid risk tracking declaration")
}

func TestResolveRiskTrackingDuplicateDeclarations(t *testing.T) {
	model := newRiskTrackingTestModel(
		map[string]*RiskTracking{
			"cat@a":   riskTrackingDeclarationForTest(Accepted),
			" Cat@A ": riskTrackingDeclarationForTest(Mitigated),
		},
		"cat@a",
	)
	err := model.ResolveRiskTracking(false, &recordingProgressReporter{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate risk tracking declaration")
}

func TestRiskTrackingAccessorsFallbackBeforeResolution(t *testing.T) {
	model := newRiskTrackingTestModel(
		map[string]*RiskTracking{
			"cat@a": riskTrackingDeclarationForTest(Accepted),
			"cat@*": riskTrackingDeclarationForTest(Mitigated),
		},
		"cat@a", "cat@b",
	)
	// exact declarations are usable even when the model was constructed without running
	// the analysis resolution ...
	assert.True(t, model.IsRiskTracked(model.GeneratedRisksBySyntheticId["cat@a"]))
	assert.Equal(t, Accepted, model.GetRiskTrackingWithDefault(model.GeneratedRisksBySyntheticId["cat@a"]).Status)
	// ... while wildcard patterns are not expanded outside of a resolution run
	assert.False(t, model.IsRiskTracked(model.GeneratedRisksBySyntheticId["cat@b"]))
	assert.Nil(t, model.GetRiskTracking(model.GeneratedRisksBySyntheticId["cat@b"]))
}
