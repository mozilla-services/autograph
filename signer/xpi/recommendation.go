package xpi // import "github.com/mozilla-services/autograph/signer/xpi"

import (
	"encoding/json"
	"fmt"
	"time"
)

// Recommendation represents an Addon Recommendation file
type Recommendation struct {
	// AddOnID is the ID of the extension this recommendation is
	// for. Must match the ID in the extension’s manifest.json
	AddOnID string `json:"addon_id"`

	// States is a list of strings for each state of an addon that
	// firefox understands
	States []string `json:"states"`

	// Validity is a pair of timestamps to expire a recommendation
	// after an appropriate amount of time, since the
	// recommendation is for a given version of the addon and it
	// will need to be reissued for new versions.
	Validity map[string]time.Time `json:"validity"`

	// SchemaVersion is a uint to allow gradual upgrades of the
	// recommendation file
	SchemaVersion int `json:"schema_version"`
}

// Recommend returns a Recommendation for param addonID with param states
func Recommend(addonID string, states []string, notBefore, notAfter time.Time) *Recommendation {
	rec := &Recommendation{
		AddOnID: addonID,
		States:  states,
		Validity: map[string]time.Time{
			"not_before": notBefore,
			"not_after":  notAfter,
		},
		SchemaVersion: 1,
	}
	return rec
}

func validateValidityTime(t time.Time) error {
	if t.Nanosecond() != 0 {
		return fmt.Errorf("xpi: time must not include nanoseconds")
	}
	if t.Location() != time.UTC {
		return fmt.Errorf("xpi: time must be in UTC tz")
	}
	return nil
}

// Validate checks a Recommendation's validity fields and state is in
// the allowed states
func (r *Recommendation) Validate(allowedRecommendationStates map[string]bool) error {
	if len(r.States) < 1 {
		return fmt.Errorf("xpi: recommendation must include at least one state")
	}
	for _, state := range r.States {
		if _, ok := allowedRecommendationStates[state]; !ok {
			return fmt.Errorf("xpi: recommendation included the invalid state %q", state)
		}
	}

	if len(r.Validity) != 2 {
		return fmt.Errorf("xpi: recommendation must include validity with not_before and not_after fields")
	}
	if _, ok := r.Validity["not_before"]; !ok {
		return fmt.Errorf("xpi: recommendation validity with missing not_before field")
	}
	if _, ok := r.Validity["not_after"]; !ok {
		return fmt.Errorf("xpi: recommendation validity with missing not_after field")
	}
	if !r.Validity["not_before"].Before(r.Validity["not_after"]) {
		return fmt.Errorf("xpi: recommendation validity not_after must be after not_before field")
	}
	err := validateValidityTime(r.Validity["not_before"])
	if err != nil {
		return fmt.Errorf("xpi: validity not_before is invalid: %w", err)
	}
	err = validateValidityTime(r.Validity["not_after"])
	if err != nil {
		return fmt.Errorf("xpi: validity not_after is invalid: %w", err)
	}
	if r.SchemaVersion != 1 {
		return fmt.Errorf("xpi: recommendation schema_version %d must be 1", r.SchemaVersion)
	}
	return nil
}

// UnmarshalRecommendation parses a recommendation file from JSON
func UnmarshalRecommendation(input []byte) (r *Recommendation, err error) {
	err = json.Unmarshal(input, &r)
	if err != nil {
		return nil, fmt.Errorf("xpi: failed to unmarshal recommendation from JSON: %w", err)
	}
	return r, nil
}

// Marshal serializes a Recommendation to JSON
func (r *Recommendation) Marshal() ([]byte, error) {
	buf, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("xpi: failed to marshal recommendation to JSON: %w", err)
	}
	return buf, nil
}

// makeRecommendationFile creates and validates a recommendation file
// using the signer config and request options
func (s *XPISigner) makeRecommendationFile(opt Options, cn string) ([]byte, error) {
	if s.Mode != ModeAddOnWithRecommendation {
		return nil, fmt.Errorf("xpi: cannot make recommendation file for signer in mode %q", s.Mode)
	}

	recommendedStatesRequested, err := opt.RecommendationStates(s.recommendationAllowedStates)
	if err != nil {
		return nil, fmt.Errorf("xpi: error parsing recommendations from options: %w", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	notBefore := now.Add(s.recommendationValidityRelativeStart)
	notAfter := notBefore.Add(s.recommendationValidityDuration)

	rec := Recommend(cn, recommendedStatesRequested, notBefore, notAfter)
	err = rec.Validate(s.recommendationAllowedStates)
	if err != nil {
		return nil, fmt.Errorf("xpi: recommendation validation failed: %w", err)
	}
	return rec.Marshal()
}

// ReadAndVerifyRecommendationFile reads and verifies the
// recommendation file from an XPI for a signer's config and returns
// the file bytes and an error when verification fails
func (s *XPISigner) ReadAndVerifyRecommendationFile(signedXPI []byte) (recFileBytes []byte, err error) {
	recFileBytes, err = readFileFromZIP(signedXPI, s.recommendationFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read recommendation file from %q: %w", s.recommendationFilePath, err)
	}
	rec, err := UnmarshalRecommendation(recFileBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal recommendation file: %w", err)
	}
	err = rec.Validate(s.recommendationAllowedStates)
	if err != nil {
		return nil, fmt.Errorf("failed to validate recommendation: %w", err)
	}
	return recFileBytes, nil
}
