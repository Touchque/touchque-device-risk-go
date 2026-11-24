# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Go modules are versioned via git tags (e.g. `v1.0.0`), not a manifest field;
the version below is the tag this module should be released under next.

## [1.0.0] — 2026-11-24

### Added
- **Touchque Device Risk as its own module**, `github.com/Touchque/touchque-device-risk-go` (package `devicerisk`). Device risk leaves the main Go SDK (6.0.0 no longer has `Client.DeviceRisk`): `devicerisk.New(config ...*Config)` and `devicerisk.NewClient(*Config)` with their own small client (the same API key and secret, `TQ_API_KEY` / `TQ_API_SECRET` / `TQ_API_URL`, the same request signing, timeout and errors as the main SDK: `*APIError` with the `ErrFeature*` sentinels, `*NetworkError`, `*ConfigError`).
- `Check(ctx, CheckOptions)` (`POST /device-risk/check`), `GetEvent(ctx, requestID)` (`GET /device-risk/events/{requestId}`), `SearchEvents(ctx, SearchOptions)` (`GET /device-risk/events`) and `ParseCheck`, as they were on `Client.DeviceRisk` (the types lose their `DeviceRisk` prefix: `CheckOptions`, `CheckResult`, `Signal`, `SearchOptions`, `SearchResult`; `DeviceRiskEvents` / `DeviceRiskReports` are `CheckEvents` / `Reports`).
- **`Activity(ctx, ActivityOptions)`: report what a visitor did that your server saw** (`POST /device-risk/activity`): `Type` (`payment_attempt`, `login_failed`, `not_found`, `forbidden`, `otp_sent`, `code_failed`), `RequestID`, `VisitorID`, `ClientIP`, `ExternalUsername`, `Outcome` (`approved`, `declined`, `error`), `Card` (`*Card{BIN, Last4}`), `Phone`, `Path`. Returns `*ActivityResult` (`Recorded`, `VisitorID`, `PathClass`, `Signals`: `abuse_card_testing`, `abuse_card_shared`, `abuse_login_failures`, `abuse_probing`, `abuse_otp_pumping`, `abuse_code_guessing`). A `Card` that is not exactly a 6-8 digit BIN and 4 last digits (a card number) is a `*ConfigError` before anything is sent. `ActivityBody`, `ParseActivity`.
- `CheckResult.Suspect` (`*Suspect`: the suspect score in shadow, `Score` 0-100, `Band`, `WouldDo`, `Mode`, `Reasons` with `Code`, `Points`, `By`, `Text`) and `CheckResult.AccountDevice` (`*AccountDevice`: `Status` known, likely, new or first, `VisitorID`, `Since`); `ParseSuspect` and `ParseAccountDevice` read them from `GetEvent` answers and `SearchEvents` rows. `MatchedBy` lists `fpc` (the first-party cookie).
- `EventDeviceRiskSignal` and `EventDeviceRiskAlert` (were in the main SDK's webhook constants).
- `CheckResult.Bot` documents `type` (`ai_agent`, `automation`, `script` or nil), `tools`, `agent` and `input` on servers since 2026-11-24; `Signal.Code` lists `device_pointer_synthetic`, `device_new_storage_burst`, `device_network_signup_burst`, `device_input_synthetic` and `device_ai_agent`.
