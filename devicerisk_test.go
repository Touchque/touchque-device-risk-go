package devicerisk

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// Device risk against the shared fake API: the report goes through untouched
// and the answer fails toward asking. Same scenarios as the Node package's tests.

func TestCheckSendsTheReportAndReadsTheAnswer(t *testing.T) {
	api := startFakeAPI(t)
	dr := api.client(t)
	r, err := dr.Check(context.Background(), CheckOptions{RequestID: "dre_flaggedaaaaaaaaaaaaaaa", Event: "sign_up", ExternalUsername: "ayse@acme.com", ClientIP: "203.0.113.7"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Report != "ok" || r.VisitorID != "tqv_fakeVisitor00000001" || len(r.Signals) != 1 || r.Signals[0].Code != "device_many_accounts" || r.Signals[0].Enforced || r.CaseCode != "DRK-2QX" {
		t.Fatalf("answer: %+v", r)
	}
	ev, err := dr.GetEvent(context.Background(), "dre_aaaaaaaaaaaaaaaaaaaaaa")
	if err != nil || ev["visitorId"] != "tqv_fakeVisitor00000001" {
		t.Fatalf("event: %v %v", ev, err)
	}
	if r.StepUp || !r.WouldStepUp || r.Mode != "shadow" || r.Suspect != nil || r.AccountDevice != nil {
		t.Fatalf("verdict: %+v", r)
	}
	relay, err := dr.Check(context.Background(), CheckOptions{DeviceRisk: "REPORT"})
	if err != nil || len(relay.Signals) != 0 {
		t.Fatalf("relay: %+v %v", relay, err)
	}
}

func TestBadInputFailsBeforeAnyRequest(t *testing.T) {
	api := startFakeAPI(t)
	dr := api.client(t)
	var cfg *ConfigError
	if _, err := dr.Check(context.Background(), CheckOptions{DeviceRisk: "r", Event: "tracking"}); !errors.As(err, &cfg) {
		t.Fatalf("unknown page: %v", err)
	}
	if _, err := dr.GetEvent(context.Background(), "../users"); !errors.As(err, &cfg) {
		t.Fatalf("bad request id: %v", err)
	}
	if _, err := dr.SearchEvents(context.Background(), SearchOptions{Limit: 101}); !errors.As(err, &cfg) {
		t.Fatalf("limit: %v", err)
	}
	if n := len(api.calls()); n != 0 {
		t.Fatalf("%d calls were sent", n)
	}
}

func TestTheAnswerFailsTowardAsking(t *testing.T) {
	if !ParseCheck(map[string]interface{}{}).StepUp || !ParseCheck(nil).StepUp {
		t.Fatal("an answer without stepUp must ask")
	}
	if ParseCheck(map[string]interface{}{"stepUp": false}).StepUp {
		t.Fatal("stepUp false is false")
	}
	r := ParseCheck(map[string]interface{}{"signals": []interface{}{map[string]interface{}{"code": "device_tampered", "text": "t"}, nil, map[string]interface{}{"text": "x"}}, "requires": "passkey"})
	if len(r.Signals) != 1 || r.Signals[0].Strength != "number_match" || r.Requires != "passkey" || r.Report != "invalid" {
		t.Fatalf("parsed: %+v", r)
	}
}

func TestEngineUnavailableComesThroughAndANormalAnswerHasNone(t *testing.T) {
	down := ParseCheck(map[string]interface{}{"report": "ok", "signals": []interface{}{}, "stepUp": true, "wouldStepUp": true,
		"requires": "number_match", "mode": "enforce", "engine": "unavailable"})
	if down.Engine != "unavailable" || !down.StepUp || down.Requires != "number_match" {
		t.Fatalf("engine unavailable: %+v", down)
	}
	normal := ParseCheck(map[string]interface{}{"report": "ok", "signals": []interface{}{}, "stepUp": false, "requires": "none", "mode": "shadow"})
	if normal.Engine != "" || normal.StepUp {
		t.Fatalf("normal answer: %+v", normal)
	}
	if ParseCheck(map[string]interface{}{"engine": 42.0}).Engine != "" {
		t.Fatal("an engine that is not a string is left out")
	}
}

func TestTheFormFieldAsItCameIsAnsweredNeverAnError(t *testing.T) {
	api := startFakeAPI(t)
	dr := api.client(t)
	r, err := dr.Check(context.Background(), CheckOptions{RequestID: "", ExternalUsername: "ayse@acme.com"})
	if err != nil || r.Report != "missing" || r.VisitorID != "" || r.StepUp || !r.WouldStepUp {
		t.Fatalf("missing: %+v %v", r, err)
	}
	if len(r.Signals) != 1 || r.Signals[0].Code != "device_identification_missing" {
		t.Fatalf("signals: %+v", r.Signals)
	}
	if r, err := dr.Check(context.Background(), CheckOptions{RequestID: "nope"}); err != nil || r.Report != "unknown" {
		t.Fatalf("unknown: %+v %v", r, err)
	}
	if ParseCheck(map[string]interface{}{"report": "expired"}).Report != "expired" {
		t.Fatal("expired")
	}
}

func TestTheAddressTheCountsAndABotAnswerComeThrough(t *testing.T) {
	r := ParseCheck(map[string]interface{}{"report": "ok", "network": map[string]interface{}{"type": "hosting"},
		"velocity": map[string]interface{}{"identifications1h": 2.0}, "bot": map[string]interface{}{"result": "suspected"}})
	if r.Network["type"] != "hosting" || r.Velocity["identifications1h"] != 2.0 || r.Bot["result"] != "suspected" {
		t.Fatalf("network, velocity, bot: %#v %#v %#v", r.Network, r.Velocity, r.Bot)
	}
	if ParseCheck(map[string]interface{}{"network": "x"}).Network != nil {
		t.Fatal("a network that is not an object is left out")
	}
}

func TestTheSuspectScoreAndTheAccountDeviceAreRead(t *testing.T) {
	r := ParseCheck(map[string]interface{}{"report": "ok",
		"suspect": map[string]interface{}{"score": 64.0, "band": "high", "wouldDo": "passkey", "mode": "shadow", "reasons": []interface{}{
			map[string]interface{}{"code": "abuse_card_testing", "points": 40.0, "by": "site", "text": "Cards tested"},
			map[string]interface{}{"code": "known_browser", "points": -10.0, "by": "server", "text": "Seen before"},
			"junk",
		}},
		"accountDevice": map[string]interface{}{"status": "likely", "visitorId": "tqv_other00000000000000"},
	})
	want := &Suspect{Score: 64, Band: "high", WouldDo: "passkey", Mode: "shadow", Reasons: []SuspectReason{
		{Code: "abuse_card_testing", Points: 40, By: "site", Text: "Cards tested"},
		{Code: "known_browser", Points: -10, By: "server", Text: "Seen before"},
	}}
	if !reflect.DeepEqual(r.Suspect, want) {
		t.Fatalf("suspect: %+v", r.Suspect)
	}
	if !reflect.DeepEqual(r.AccountDevice, &AccountDevice{Status: "likely", VisitorID: "tqv_other00000000000000"}) {
		t.Fatalf("accountDevice: %+v", r.AccountDevice)
	}
	if ParseSuspect(map[string]interface{}{"score": "x"}) != nil || ParseSuspect(map[string]interface{}{"score": 1.5}) != nil {
		t.Fatal("a score that is not a whole number is no suspect score")
	}
	if s := ParseSuspect(map[string]interface{}{"score": 130.0}); s.Score != 100 || s.Band != "critical" || s.WouldDo != "allow" {
		t.Fatalf("clamped: %+v", s)
	}
	if ParseAccountDevice(map[string]interface{}{"status": "maybe"}) != nil {
		t.Fatal("an unknown status is no account device")
	}
	if !contains(MatchedBy, "fpc") {
		t.Fatal("matchedBy fpc")
	}
}

func TestSearchEventsPagesWithTheOpaqueCursorAndSendsTheFilters(t *testing.T) {
	api := startFakeAPI(t)
	dr := api.client(t)
	no := false
	first, err := dr.SearchEvents(context.Background(), SearchOptions{Account: "ada@example.com", StepUp: &no, IP: "203.0.113.0/24", Limit: 1})
	if err != nil || len(first.Events) != 1 || first.Events[0]["requestId"] != "dre_fakeEvent00000000002" || first.NextCursor != "" {
		t.Fatalf("first: %+v %v", first, err)
	}
	q := api.lastDeviceRiskSearch()
	if q["account"] != "ada@example.com" || q["stepUp"] != "false" || q["ip"] != "203.0.113.0/24" || q["limit"] != "1" || len(q) != 4 {
		t.Fatalf("query: %v", q)
	}
	var seen []string
	cursor := ""
	for {
		page, err := dr.SearchEvents(context.Background(), SearchOptions{Limit: 1, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Events {
			seen = append(seen, e["requestId"].(string))
		}
		if cursor = page.NextCursor; cursor == "" {
			break
		}
	}
	if len(seen) != 3 || seen[0] != "dre_fakeEvent00000000003" || seen[2] != "dre_fakeEvent00000000001" {
		t.Fatalf("pages: %v", seen)
	}
}

func TestFeatureRefusalsMatchTheirSentinels(t *testing.T) {
	api := startFakeAPI(t)
	dr := api.client(t)
	cases := map[string]error{"feature_not_in_plan": ErrFeatureNotInPlan, "feature_read_only": ErrFeatureReadOnly, "feature_off": ErrFeatureOff}
	for code, sentinel := range cases {
		api.opts(map[string]interface{}{"featureRefused": code, "feature": "device_risk"})
		_, err := dr.Check(context.Background(), CheckOptions{RequestID: "dre_aaaaaaaaaaaaaaaaaaaaaa"})
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 || apiErr.Feature != "device_risk" {
			t.Fatalf("%s: want a 403 *APIError for device_risk, got %v", code, err)
		}
		if !errors.Is(err, sentinel) || !errors.Is(err, ErrFeature) {
			t.Fatalf("%s: errors.Is does not match its sentinel", code)
		}
	}
}

func TestAnAPIErrorCarriesItsStatusAndCode(t *testing.T) {
	api := startFakeAPI(t)
	_, err := api.client(t).GetEvent(context.Background(), "dre_unknownaaaaaaaaaaaaaaa")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 404 || apiErr.Code != "not_found" || errors.Is(err, ErrFeature) {
		t.Fatalf("want a 404 not_found, got %v", err)
	}
}

func TestNewReadsTheEnvironment(t *testing.T) {
	t.Setenv("TQ_API_KEY", "")
	t.Setenv("TQ_API_SECRET", "")
	var cfg *ConfigError
	if _, err := New(); !errors.As(err, &cfg) {
		t.Fatalf("missing keys: %v", err)
	}
	if _, err := New(&Config{APIKey: "wrong", APISecret: "s"}); !errors.As(err, &cfg) {
		t.Fatalf("wrong key: %v", err)
	}
	t.Setenv("TQ_API_KEY", "tq_env")
	t.Setenv("TQ_API_SECRET", "env_secret")
	if _, err := New(); err != nil {
		t.Fatal(err)
	}
}

func TestTheWebhookEventNames(t *testing.T) {
	if EventDeviceRiskSignal != "DEVICE_RISK_SIGNAL" || EventDeviceRiskAlert != "DEVICE_RISK_ALERT" {
		t.Fatal("webhook event names")
	}
}
