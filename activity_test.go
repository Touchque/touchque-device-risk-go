package devicerisk

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Activity: what the server saw, against the shared fake Touchque API. A card number never leaves.

func TestActivityAPaymentIsSentAndRecorded(t *testing.T) {
	api := startFakeAPI(t)
	a, err := api.client(t).Activity(context.Background(), ActivityOptions{Type: "payment_attempt", RequestID: "dre_aaaaaaaaaaaaaaaaaaaaaa",
		ClientIP: "203.0.113.7", ExternalUsername: "ayse@acme.com", Outcome: "declined", Card: &Card{BIN: "411111", Last4: "1111"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, &ActivityResult{Recorded: true, VisitorID: "tqv_fakeVisitor00000001", Signals: []string{}}) {
		t.Fatalf("answer: %+v", a)
	}
	want := map[string]interface{}{"type": "payment_attempt", "requestId": "dre_aaaaaaaaaaaaaaaaaaaaaa", "clientIp": "203.0.113.7",
		"externalUsername": "ayse@acme.com", "outcome": "declined", "card": map[string]interface{}{"bin": "411111", "last4": "1111"}}
	if got := api.lastDeviceRiskActivity(); !reflect.DeepEqual(got, want) {
		t.Fatalf("body: %v", got)
	}
}

func TestActivityAFlaggedVisitorRaisesCardTesting(t *testing.T) {
	api := startFakeAPI(t)
	a, err := api.client(t).Activity(context.Background(), ActivityOptions{Type: "payment_attempt", RequestID: "dre_flaggedaaaaaaaaaaaaaaa",
		Outcome: "declined", Card: &Card{BIN: "41111111", Last4: "0004"}})
	if err != nil || !a.Recorded || !reflect.DeepEqual(a.Signals, []string{"abuse_card_testing"}) {
		t.Fatalf("flagged: %+v %v", a, err)
	}
}

func TestActivityAProbedPathAnswersItsClass(t *testing.T) {
	api := startFakeAPI(t)
	a, err := api.client(t).Activity(context.Background(), ActivityOptions{Type: "not_found", ClientIP: "203.0.113.7", Path: "/.env"})
	if err != nil || a.PathClass != "secrets" || a.VisitorID != "" || len(a.Signals) != 0 {
		t.Fatalf("path: %+v %v", a, err)
	}
}

func TestActivityACardNumberIsRefusedBeforeAnythingIsSent(t *testing.T) {
	api := startFakeAPI(t)
	dr := api.client(t)
	for _, card := range []*Card{{BIN: "4111111111111111", Last4: "1111"}, {BIN: "411111", Last4: "4111111111111111"},
		{BIN: "4111111111111111"}, {BIN: "411111", Last4: "111"}, {BIN: "41111", Last4: "1111"}, {BIN: "41111a", Last4: "1111"}, {}} {
		_, err := dr.Activity(context.Background(), ActivityOptions{Type: "payment_attempt", ClientIP: "203.0.113.7", Card: card})
		var cfg *ConfigError
		if !errors.As(err, &cfg) || !strings.Contains(cfg.Message, "never send the card number") {
			t.Fatalf("%+v: want a *ConfigError, got %v", card, err)
		}
	}
	if n := len(api.calls()); n != 0 {
		t.Fatalf("%d calls were sent", n)
	}
	if got := api.lastDeviceRiskActivity(); len(got) != 0 {
		t.Fatalf("an activity reached the API: %v", got)
	}
}

func TestActivityWrongFieldsAreRefusedBeforeAnyRequest(t *testing.T) {
	api := startFakeAPI(t)
	dr := api.client(t)
	for _, opts := range []ActivityOptions{
		{Type: "tracking", ClientIP: "203.0.113.7"},
		{ClientIP: "203.0.113.7"},
		{Type: "login_failed"},
		{Type: "payment_attempt", ClientIP: "203.0.113.7", Outcome: "maybe"},
		{Type: "otp_sent", ClientIP: "203.0.113.7", Phone: "call me"},
		{Type: "login_failed", ClientIP: "203.0.113.7", ExternalUsername: strings.Repeat("a", 256)},
		{Type: "not_found", ClientIP: "203.0.113.7", Path: "/" + strings.Repeat("a", 2048)},
	} {
		var cfg *ConfigError
		if _, err := dr.Activity(context.Background(), opts); !errors.As(err, &cfg) {
			t.Fatalf("%+v: want a *ConfigError, got %v", opts, err)
		}
	}
	if n := len(api.calls()); n != 0 {
		t.Fatalf("%d calls were sent", n)
	}
}

func TestActivityTheAnswerIsReadStrictly(t *testing.T) {
	if a := ParseActivity(nil); a.Recorded || a.VisitorID != "" || len(a.Signals) != 0 {
		t.Fatalf("nil: %+v", a)
	}
	a := ParseActivity(map[string]interface{}{"recorded": "yes", "signals": []interface{}{"abuse_probing", 7.0}, "pathClass": "nowhere"})
	if a.Recorded || a.PathClass != "" || !reflect.DeepEqual(a.Signals, []string{"abuse_probing"}) {
		t.Fatalf("strict: %+v", a)
	}
}
