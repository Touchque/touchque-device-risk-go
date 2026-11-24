package devicerisk

import (
	"errors"
	"fmt"
)

// APIError represents an error returned by the Touchque API (status >= 400).
type APIError struct {
	StatusCode int
	Message    string
	// Code is the machine-readable error code (e.g. "device_risk_off",
	// "card_number_not_allowed"), when the API sent one.
	Code string
	// RetryAfter: seconds to wait before retrying (429).
	RetryAfter int
	// CaseCode is the "Why?" case code of a refusal (K7P-2QX): your team opens
	// the decision by it in the dashboard. Empty for other errors.
	CaseCode string
	// Feature is the catalog id (device_risk) of a feature refusal; see
	// ErrFeatureNotInPlan. Empty for other errors.
	Feature string
	Data    map[string]interface{}
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Touchque API Error (HTTP %d): %s", e.StatusCode, e.Message)
}

// The organization behind your workspace cannot use Device risk here (HTTP
// 403). An *APIError matches one of these with errors.Is, and ErrFeature for
// any of the three; its Feature field names the feature:
//   - ErrFeatureNotInPlan: not in its plan (feature_not_in_plan); an owner or
//     admin adds it in the Touchque dashboard;
//   - ErrFeatureReadOnly: being turned off (feature_read_only); reads still
//     work for 14 days, changes are refused;
//   - ErrFeatureOff: switched off on this Touchque deployment (feature_off).
var (
	ErrFeature          = errors.New("touchque: feature not available")
	ErrFeatureNotInPlan = errors.New("touchque: feature not in the organization's plan")
	ErrFeatureReadOnly  = errors.New("touchque: feature is being turned off (read-only)")
	ErrFeatureOff       = errors.New("touchque: feature switched off on this deployment")
)

var featureErrors = map[string]error{
	"feature_not_in_plan": ErrFeatureNotInPlan,
	"feature_read_only":   ErrFeatureReadOnly,
	"feature_off":         ErrFeatureOff,
}

// Is lets errors.Is match the feature sentinels.
func (e *APIError) Is(target error) bool {
	code, _ := e.Data["error"].(string)
	sentinel, ok := featureErrors[code]
	if !ok {
		return false
	}
	return target == ErrFeature || target == sentinel
}

// NetworkError means the request never reached the API (DNS, connection, timeout).
type NetworkError struct {
	Message string
}

func (e *NetworkError) Error() string {
	return e.Message
}

// ConfigError means invalid or missing configuration, or a wrong argument
// (returned before any request).
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}
