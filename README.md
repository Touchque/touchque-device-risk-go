# touchque-device-risk-go

The official Go server SDK for **Touchque Device Risk**: a visitor ID for every browser on your
sign-up, password-reset, sign-in or approval page, a risk verdict for the account it is used for, and
the abuse your server sees (card testing, failed sign-ins, probing, SMS pumping, code guessing).

Device Risk is a paid add-on: it answers 409 `device_risk_off` until your workspace turns it on in the
[Touchque dashboard](https://dashboard.touchque.com).

Full docs: **[support.touchque.com](https://support.touchque.com)**

## Install

```bash
go get github.com/Touchque/touchque-device-risk-go
```

Only the standard library; Go 1.26 or newer.

## Setup

The same API key and secret as the main Touchque SDK:

```bash
TQ_API_KEY=tq_your_key
TQ_API_SECRET=your_api_secret
```

```go
import devicerisk "github.com/Touchque/touchque-device-risk-go"

dr, err := devicerisk.New() // reads the environment
dr = devicerisk.NewClient(&devicerisk.Config{APIKey: key, APISecret: secret, TimeoutMs: 10000}) // panics on a bad config
```

Every call is signed with your API secret: keep it on your server. A `*Client` is safe for concurrent use.

## Check a page's identification

The page identifies the browser with `@touchque/device-risk` (the script tag `device.js` fills a
`touchque_request_id` field in your form, or `identify({ siteKey, purpose })` gives a `requestId`). Never
trust the page's copy: check it on your server.

```go
r, err := dr.Check(ctx, devicerisk.CheckOptions{
	RequestID:        req.FormValue("touchque_request_id"),
	Event:            "sign_up",
	ExternalUsername: email,
	ClientIP:         ip,
})
if err == nil && r.StepUp {
	askForEmailCode() // a step-up, never a refusal on it alone
}
```

- Pass the field as it came: missing, empty, made up or expired is still a verdict (`Report`:
  `missing`, `unknown`, `expired`, `invalid`; the signal `device_identification_missing`), never an error.
- `Event`: `sign_in` (default), `sign_up`, `password_reset` or `approval` (`CheckEvents`).
- `*CheckResult` fails toward asking: `StepUp` is true unless the API says exactly false.
- `Suspect` is the suspect score, in shadow (it decides nothing yet): `Score` 0-100, `Band`
  (low, medium, high, critical), `WouldDo` (allow, number_match, passkey, block) and `Reasons`
  (`Code`, `Points`, `By`: server, site, page or brand, `Text`).
- `AccountDevice`: did this account use the device before? `Status` known, likely, new or first.

For a sign-in approved on the phone with the main Touchque SDK, pass the same field as
`DeviceRiskRequestID` in its `LoginRequestOptions` or `RiskCheckOptions` instead.

## Read and search identifications

```go
ev, err := dr.GetEvent(ctx, "dre_...") // the trusted identification, the verdict, accountDevice, suspect
suspect := devicerisk.ParseSuspect(ev["suspect"])

stepUp := true
cursor := ""
for {
	page, err := dr.SearchEvents(ctx, devicerisk.SearchOptions{Account: "ada@example.com", StepUp: &stepUp, Limit: 50, Cursor: cursor})
	if err != nil {
		break
	}
	for _, e := range page.Events { /* requestId, at, visitorId, kind, matchedBy, signals, suspect… */ }
	if cursor = page.NextCursor; cursor == "" {
		break
	}
}
```

Filters: `From`, `To` (7 days by default, at most 90), `Signal`, `StepUp`, `Kind`, `Origin`, `IP` (an
address or a CIDR range, never returned), `Account`, `VisitorID`, `RequestID`, `Limit` (1 to 100) and the
opaque `Cursor`. A search that would read too much is a 422 `search_too_broad`.

## Report what your server saw

```go
a, err := dr.Activity(ctx, devicerisk.ActivityOptions{
	Type:             "payment_attempt",
	RequestID:        req.FormValue("touchque_request_id"),
	ClientIP:         ip,
	ExternalUsername: email,
	Outcome:          "declined",                                   // what the payment provider answered
	Card:             &devicerisk.Card{BIN: "411111", Last4: "1111"}, // never the card number
})
if err == nil && slices.Contains(a.Signals, "abuse_card_testing") {
	stopTakingCards()
}
```

- `Type`: `payment_attempt`, `login_failed`, `not_found`, `forbidden` (with `Path`), `otp_sent` (with
  `Phone`), `code_failed` (a wrong coupon or gift-card code).
- Name the visitor with `RequestID`, `VisitorID` or `ClientIP` (a bot that never runs your page still
  counts on its network).
- `*ActivityResult`: `Recorded`, `VisitorID`, `Signals` (`abuse_card_testing`, `abuse_card_shared`,
  `abuse_login_failures`, `abuse_probing`, `abuse_otp_pumping`, `abuse_code_guessing`) and, for a path,
  `PathClass`. For 24 hours the visitor's next checks carry those signals and the suspect score weighs them.
- A card is its BIN (6 to 8 digits) and last 4 digits only; anything else is a `*ConfigError` before
  anything is sent.

## Webhooks

Verify Touchque webhooks with the main Touchque SDK, then compare `event` with
`devicerisk.EventDeviceRiskSignal` (a signal that asks for more) or `devicerisk.EventDeviceRiskAlert`
(an alert rule of the workspace went off).

## Errors

- `*ConfigError`: a wrong argument or configuration (nothing was sent).
- `*APIError`: the API answered an error (`StatusCode`, `Code`, `RetryAfter`, `CaseCode`, `Feature`).
  `errors.Is(err, devicerisk.ErrFeature)` (or `ErrFeatureNotInPlan`, `ErrFeatureReadOnly`, `ErrFeatureOff`):
  Device risk is not in your organization's plan, being turned off, or switched off on this deployment.
- `*NetworkError`: the request never reached Touchque.

## Tests

```bash
go test ./...
```

The tests run against the shared fake Touchque API (`testing/fake-touchque-api.mjs`, Node.js).

## License

MIT
