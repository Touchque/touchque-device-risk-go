# touchque-device-risk-go

The official Go server SDK for **Touchque Device Risk**: a visitor ID for every browser on your
sign-up, password-reset, sign-in or approval page, a risk verdict for the account it is used for, and
the abuse your server sees (card testing, failed sign-ins, probing, SMS pumping, code guessing), and which
bot sent a request your page's tag never saw.

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
- `Network` is the address as the risk engine saw it, with the kind of network (see [The network](#the-network)).
- `Bot` is one answer to "a bot?" (`result`, `reasons`, `type`, `tools`, `agent`, `input`), a map as the API
  sent it. `tools` names the automation tools (`selenium`, `playwright`, `puppeteer`, `phantomjs`,
  `nightmare`, `headless_chrome`) and the AI agents whose marks were on the page: `claude_agent` (the Claude
  app's browser or Claude in Chrome), `comet_agent` (Perplexity Comet), `genspark_agent`, `browser_use`,
  `stagehand` and `skyvern`; each is `tool_<name>` in `reasons`. Other reasons include `cdp` (the DevTools
  protocol attached), `cdp_input` (a press with no pressure), `input_no_focus` (a click or key into a page
  that was not in front), `insert_text_bulk` (text with no key pressed), `scripted_click` (a form sent with
  no click or key), `headless_window` and `emulator`. New tools and reasons may be added in minor versions;
  older servers send fewer.

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
	for _, e := range page.Events { /* requestId, at, visitorId, kind, network, matchedBy, signals, suspect… */ }
	if cursor = page.NextCursor; cursor == "" {
		break
	}
}
```

Filters: `From`, `To` (7 days by default, at most 90), `Signal`, `StepUp`, `Kind` (the page), `Origin`,
`IP` (an address or a CIDR range, never returned), `Account`, `VisitorID`, `RequestID`, `NetworkKind` and
`Shared` (see [The network](#the-network)), `Limit` (1 to 100) and the opaque `Cursor`. A search that would
read too much is a 422 `search_too_broad`.

## The network

`Network` (in `Check`, `GetEvent` and each `SearchEvents` row) is the address as the risk engine saw it,
never coordinates, as a map: `countryCode`, `city`, `asn`, `asnOrg`, `type` (`isp`, `hosting`, `tor`,
`relay` for Apple's iCloud Private Relay, `unknown`), `proxy` and more. Newer servers also say what kind of
network it is (absent on older ones, nil for an identification from before it). `kind` is one of
`devicerisk.NetworkKinds` (`residential`, `mobile_carrier`, `education`, `business`, `public_wifi`,
`hosting`, `proxy`, `vpn`, `tor`, `relay`, `unknown`): an open list, new values may be added in minor
versions, so keep a default branch. `kindSource` says where it came from. `vpn` is a VPN company's own
address (the suspect score's `network_vpn`, 10 points). `shared` means many browsers used the
identification's own address on your pages in 24 hours (a school, an office, a café or a mobile operator;
context only), with `sharedVisitors24h` and `sharedAccounts24h` as "at least" counts (1, 2, 5, 10, 100 or
1000). `lookAlikeMatching` is false when this computer was recognised only by its own key, cookie or stored
id, never because it looks like another one, and nil when not decided (phones, tablets and Safari are never
matched by look-alike). The shared fields and `lookAlikeMatching` are nil when not counted, or when
`ClientIP` was another address than the one the browser identified from. `proxy` means the address was
reported as a proxy in the last 30 days: context that counts little (absent on older servers). In
`SearchEvents`, `NetworkKind` matches only identifications classified since network kind exists (older ones
have no kind), and `Shared` set to false matches only the ones counted and not shared (one that was not
counted matches neither). Older servers ignore both filters.

Touchque uses the IP2Proxy LITE database for [proxy and VPN detection](https://www.ip2location.com).
This site or product includes IP2Proxy LITE data available from https://lite.ip2location.com.

```go
kind, _ := r.Network["kind"].(string)                  // "" from an older server or identification
atLeast, _ := r.Network["sharedVisitors24h"].(float64) // JSON numbers are float64

shared := true
page, err := dr.SearchEvents(ctx, devicerisk.SearchOptions{NetworkKind: "education", Shared: &shared})
```

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

## Bot check

Many bots never run your page, so the tag never sees them: ChatGPT-User, GPTBot, Meta's crawlers, curl,
scripts. `BotCheck` sends one request's IP and headers from your server and answers which bot it is,
whether that name is proven, and what Touchque would do. Touchque decides on its own servers, with no
third-party service at request time, and keeps nothing but short-lived counters.

```go
http.HandleFunc("/pricing", func(w http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 500*time.Millisecond) // never hold the page for it
	defer cancel()
	b, err := dr.BotCheck(ctx, devicerisk.BotCheckRequestFrom(req, clientIP(req)))
	if err == nil && b.Bot.Result != "not_detected" {
		log.Printf("bot %s %s/%s identity=%s suggestion=%s rule=%s",
			b.Bot.Category, b.Bot.Provider, b.Bot.Name, b.Bot.Identity, b.Suggestion, b.Bot.Rule)
	}
	// ... serve the page
})
```

- `clientIP` is yours: the visitor's address as your proxy or load balancer reports it (empty:
  `req.RemoteAddr`).
- `Bot`: `Result` (detected, suspected, not_detected), `Category` (`ai_agent`, `ai_assistant`,
  `ai_crawler`, `ai_search`, `search_crawler`, `link_preview`, `seo`, `monitoring`, `archiver`,
  `feed_reader`, `security_scanner`, `http_client`, `headless_browser`, `automation`), `Provider` and
  `Name` (OpenAI, ChatGPT-User), `VerifiedBy`, `Confidence`, `Rule` and `Reasons` (`Code`, `Text`: a
  sentence for your fraud team).
- `Bot.Identity`: `verified` (its operator's signature, published addresses or reverse DNS proved it),
  `unverified` (**a spoofed name**: its operator publishes a way to check, and the check failed) or
  `claimed` (no way to check it, or not right now).
- `Network`: `ASN`, `ASNOrg`, `CountryCode`, `Hosting`; nil when Touchque cannot tell.
- `Suggestion` is **advice in shadow: Touchque never enforces it**. `allow` (a verified bot, a declared
  crawler, assistant or other bot that cannot be checked, or no bot), `block` (a spoofed name), `challenge`
  (an AI agent that only names itself, since it acts for a person; undeclared automation; or a suspected bot).
- Authorization, Cookie, Proxy-Authorization, X-Api-Key and Set-Cookie go with empty values, the URL
  without its query string, and a request with no headers as `[]`.
- What the visitor sent never makes it fail: the first 100 headers go, a name is cut to 128 characters
  and a value to 4096, the body is kept under 32 KB, and the request tells Touchque it was cut
  (`truncated`). A header HTTP does not allow, a method other than 1 to 16 letters or a URL Touchque
  could not read is left out. Only no IP (or one that is not an address) is a `*ConfigError`, before
  anything is sent.
- Go's `net/http` does not keep the order headers arrived in, so `BotCheckRequestFrom` sends them as a
  set (`HeaderOrderUnknown`). When your edge gives you the order, build `Headers` yourself in that order.
- `HTTPVersion` and `TLS` go only when you set them from what your edge saw. `BotCheckRequestFrom`
  never sets them: `r.Proto` is the connection to your server, which behind a proxy is the proxy's.
- New categories and fields may be added: they come through as strings, and `Raw` keeps the whole answer.

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

The tests run against the shared fake Touchque API (`testing/fake-touchque-api.mjs`, Node.js); the bot
check tests and the network-kind answer tests use a local `httptest` server.

## License

MIT
