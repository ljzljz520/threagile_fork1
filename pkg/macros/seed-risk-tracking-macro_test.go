package macros

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/threagile/threagile/pkg/input"
	"github.com/threagile/threagile/pkg/types"
)

type noopMacroProgressReporter struct{}

func (noopMacroProgressReporter) Info(a ...any)         {}
func (noopMacroProgressReporter) Warn(a ...any)         {}
func (noopMacroProgressReporter) Error(a ...any)        {}
func (noopMacroProgressReporter) Infof(string, ...any)  {}
func (noopMacroProgressReporter) Warnf(string, ...any)  {}
func (noopMacroProgressReporter) Errorf(string, ...any) {}

func TestSeedRiskTrackingMacroSharesResolvedRiskTracking(t *testing.T) {
	parsedModel := &types.Model{
		RiskTracking: map[string]*types.RiskTracking{
			"cat@*": {Status: types.Mitigated, Justification: "covered as a group"},
		},
		GeneratedRisksBySyntheticId: map[string]*types.Risk{
			"cat@a": {SyntheticId: "cat@a"},
			"cat@b": {SyntheticId: "cat@b"},
			"dog@x": {SyntheticId: "dog@x"},
		},
	}
	assert.NoError(t, parsedModel.ResolveRiskTracking(false, noopMacroProgressReporter{}))

	modelInput := new(input.Model).Defaults()
	modelInput.RiskTracking["cat@*"] = input.RiskTracking{Status: types.Mitigated.String()}

	message, valid, err := NewSeedRiskTracking().Execute(modelInput, parsedModel)
	assert.NoError(t, err)
	assert.True(t, valid)
	assert.Contains(t, message, "1")

	// risks already covered by the wildcard declaration are not seeded again
	assert.NotContains(t, modelInput.RiskTracking, "cat@a")
	assert.NotContains(t, modelInput.RiskTracking, "cat@b")

	// only the truly untracked risk gets an initial tracking entry
	seeded, exists := modelInput.RiskTracking["dog@x"]
	assert.True(t, exists)
	assert.Equal(t, types.Unchecked.String(), seeded.Status)

	// the original wildcard declaration in the model input is preserved
	assert.Equal(t, types.Mitigated.String(), modelInput.RiskTracking["cat@*"].Status)

	// and the parsed declarations stay untouched as well
	assert.Len(t, parsedModel.RiskTracking, 1)
	assert.Contains(t, parsedModel.RiskTracking, "cat@*")
}

func TestSeedRiskTrackingMacroSeedsAllWithoutDeclarations(t *testing.T) {
	parsedModel := &types.Model{
		RiskTracking: map[string]*types.RiskTracking{},
		GeneratedRisksBySyntheticId: map[string]*types.Risk{
			"cat@a": {SyntheticId: "cat@a"},
			"dog@x": {SyntheticId: "dog@x"},
		},
	}
	assert.NoError(t, parsedModel.ResolveRiskTracking(false, noopMacroProgressReporter{}))

	modelInput := new(input.Model).Defaults()
	_, valid, err := NewSeedRiskTracking().Execute(modelInput, parsedModel)
	assert.NoError(t, err)
	assert.True(t, valid)
	assert.Len(t, modelInput.RiskTracking, 2)
	assert.Contains(t, modelInput.RiskTracking, "cat@a")
	assert.Contains(t, modelInput.RiskTracking, "dog@x")
}
