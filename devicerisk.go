// Package devicerisk is the Go server SDK for Touchque Device Risk (a paid
// add-on, off until your workspace turns it on): a visitor ID for every
// browser on your sign-up, password-reset, sign-in or approval page, and what
// your server saw it do.
//
// The page identifies with @touchque/device-risk (the script tag, or
// identify({ siteKey, purpose }), which gives { visitorId, requestId,
// confidence }) and sends you the requestId. Never trust the page's copy:
// read the identification here (GetEvent) or check it for an account
// (Check). Touchque keeps keyed hashes only, with a key of your workspace
// alone, and its risk engine decides.
//
// Every signal only ever asks for more: StepUp means an extra check on this
// page (an emailed code, a passkey, a number-matched approval), never a
// refusal. For sign-ins approved on the phone with the main Touchque SDK,
// pass the requestId as DeviceRiskRequestID in its LoginRequestOptions and
// RiskCheckOptions instead. Collect it only on these pages and name it in
// your privacy notice.
//
// With the script tag (device.js), the form arrives with touchque_request_id:
//
//	dr, err := devicerisk.New() // TQ_API_KEY, TQ_API_SECRET
//	r, err := dr.Check(ctx, devicerisk.CheckOptions{RequestID: req.FormValue("touchque_request_id"), ExternalUsername: email})
//
// Pass it as it came. Missing, empty, made up or expired, it is still a
// verdict (Report missing, unknown, expired; the signal
// device_identification_missing), never an error: a page without the tag, or
// with it blocked, only gets the visitor a step-up.
//
// For the visitors that never run your page (ChatGPT-User, GPTBot, crawlers,
// curl, scripts), BotCheck tells from one request's IP and headers which bot
// sent it and whether that name is proven, with a suggestion in shadow:
//
//	b, err := dr.BotCheck(ctx, devicerisk.BotCheckRequestFrom(req, ip))
package devicerisk

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Client is the Touchque Device Risk client. Safe for concurrent use: create
// one and reuse it.
type Client struct {
	http *httpClient
}

// NewClient builds a Client from config. Panics on invalid configuration (as
// the main Touchque SDK's NewClient) — use New() for a version that returns
// an error instead.
func NewClient(config *Config) *Client {
	config.sanitize()
	return &Client{http: newHTTPClient(config)}
}

// New builds a Client from TQ_API_KEY / TQ_API_SECRET / TQ_API_URL, or from
// config if given (config[0], at most one).
func New(config ...*Config) (*Client, error) {
	var cfg *Config
	if len(config) > 0 && config[0] != nil {
		cfg = config[0]
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
	} else {
		c, err := ConfigFromEnv()
		if err != nil {
			return nil, err
		}
		cfg = c
	}
	return &Client{http: newHTTPClient(cfg)}, nil
}

// The event values of Device risk's webhook events. Verify the webhook with
// the main Touchque SDK (Webhook), then compare its event with these. Ignore
// types you do not know.
const (
	// EventDeviceRiskSignal: an identification or a Check raised a signal
	// that asks for more (enforced or in shadow). Never a trait.
	EventDeviceRiskSignal = "DEVICE_RISK_SIGNAL"
	// EventDeviceRiskAlert: an alert rule of the workspace went off.
	EventDeviceRiskAlert = "DEVICE_RISK_ALERT"
)

// CheckEvents are the pages a device report may come from.
var CheckEvents = []string{"sign_in", "sign_up", "password_reset", "approval"}

// Reports are what the page had sent: ok, replayed, or no usable identification.
var Reports = []string{"ok", "replayed", "missing", "unknown", "expired", "invalid"}

// MatchedBy are how a visitor was recognised (an event's matchedBy): its
// device-bound key, the first-party cookie (fpc), its stored id, its traits,
// or new.
var MatchedBy = []string{"key", "fpc", "sid", "traits", "new"}

// NetworkKinds are the kinds of network an address is on: the network's
// "kind" in Check, GetEvent and SearchEvents answers, and
// SearchOptions.NetworkKind. A VPN, hosting, a proxy company, Tor and a
// relay always win over a place. An open list: new values may be added in
// minor versions and come through as they came, so keep a default branch.
// Absent from older servers' answers.
var NetworkKinds = []string{"residential", "mobile_carrier", "education", "business", "public_wifi", "hosting", "proxy", "vpn", "tor", "relay", "unknown"}

// ActivityTypes are what your server saw the visitor do (ActivityOptions.Type).
var ActivityTypes = []string{"payment_attempt", "login_failed", "not_found", "forbidden", "otp_sent", "code_failed"}

// ActivityOutcomes are what the payment provider answered (payment_attempt).
var ActivityOutcomes = []string{"approved", "declined", "error"}

// ActivitySignals are the abuse codes an activity can raise. New codes may be added.
var ActivitySignals = []string{"abuse_card_testing", "abuse_card_shared", "abuse_login_failures", "abuse_probing", "abuse_otp_pumping", "abuse_code_guessing"}

// PathClasses are the classes of a not_found / forbidden path.
var PathClasses = []string{"admin", "wordpress", "secrets", "source", "db_admin", "debug", "shell", "other"}

var (
	requestIDPattern = regexp.MustCompile(`^dre_[A-Za-z0-9_-]{22}$`)
	binPattern       = regexp.MustCompile(`^[0-9]{6,8}$`)
	last4Pattern     = regexp.MustCompile(`^[0-9]{4}$`)
	phonePattern     = regexp.MustCompile(`^\+?[0-9]{6,15}$`)
)

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// CheckOptions is one page's identification, for an account.
type CheckOptions struct {
	// RequestID is the touchque_request_id form field (the script tag) or
	// identify()'s requestId, as it came: empty is answered Report "missing".
	RequestID string
	// DeviceRisk is instead the page's report (collect()), relayed untouched.
	DeviceRisk string
	// Event is the page: sign_in (default), sign_up, password_reset or approval.
	Event string
	// ExternalUsername is the account the page is for, when there is one. One account per identification.
	ExternalUsername string
	// ClientIP is the end user's address; default: where the browser identified from.
	ClientIP string
}

// Signal is one signal. Each one only ever asks for more.
type Signal struct {
	// Code: device_tampered, device_virtual, device_geo_mismatch,
	// device_many_accounts, device_signup_burst, device_id_resets,
	// device_many_countries, device_wrong_site, device_report_replayed,
	// device_private_window (context only), device_step_up_by_admin,
	// device_identification_missing (no identification, or one that does not verify),
	// device_pointer_synthetic (the pointer or a finger moved like software),
	// device_new_storage_burst and device_network_signup_burst (many new browsers,
	// or sign-ups, in a day on this network from devices like this one: phones,
	// or identical computers where look-alikes are not joined),
	// device_input_synthetic (typed or clicked like software) and
	// device_ai_agent (an AI agent or bot by its own signature or user agent,
	// or, on servers since 2026-11-25, an AI agent's marks on the page it
	// drives: the Claude app's browser or Claude in Chrome, Perplexity Comet,
	// Genspark, Browser Use, Stagehand, Skyvern);
	// these two ask for a number-matched step-up only, never a block. The
	// abuse codes of Activity (ActivitySignals) are carried for 24 hours too.
	// New codes are added in minor versions.
	Code string
	Text string
	// Strength is what a step-up for it should be: number_match, passkey, or none (context only).
	Strength string
	// Enforced: scored now; false means reported only (shadow) until Touchque enforces it.
	Enforced bool
	Evidence map[string]interface{}
}

// SuspectReason is one reason of the suspect score.
type SuspectReason struct {
	Code string
	// Points: negative for a known browser or a trusted mark.
	Points int
	// By is who proves it: server (Touchque saw it), site (your server
	// reported it: Activity), page (the browser reported it) or brand (your
	// admin's mark).
	By   string
	Text string
}

// Suspect is the suspect score, in shadow: it decides nothing yet.
type Suspect struct {
	// Score is 0 to 100.
	Score int
	// Band is low, medium, high or critical.
	Band string
	// WouldDo is what it would ask for: allow (0-29), number_match (30-59),
	// passkey (60+), or block (a sign-up or password reset at 80+ with a
	// reason the server proved; an existing account's sign-in is never blocked).
	WouldDo string
	// Mode is shadow.
	Mode    string
	Reasons []SuspectReason
}

// AccountDevice says whether this account used the device before (once a
// check names the account).
type AccountDevice struct {
	// Status: known (this visitor served it), likely (another of its
	// visitors has the same trait profile on the same network), new (the
	// account has other devices here, not this one) or first (none yet).
	Status string
	// VisitorID (likely): the account's visitor it looks like.
	VisitorID string
	// Since (known): the account's first identification on it, ISO 8601.
	Since string
}

// CheckResult is the answer.
type CheckResult struct {
	// Report is what the page had sent: ok; replayed (another account, or sent
	// twice); or no usable identification, which raises
	// device_identification_missing: missing (none or empty), unknown (made up,
	// or another workspace's), expired (over 15 minutes old), invalid (a relayed
	// report that cannot be read).
	Report    string
	RequestID string
	// VisitorID (tqv_…) is this browser in your workspace only.
	VisitorID  string
	Confidence float64
	// Visitor holds firstSeenAt, lastSeenAt, seenCount, matchedBy, sealed,
	// status (your admin's mark), labels and mark: the mark actually applied
	// to this identification, "step_up" always, "trusted" only when the
	// browser matched by its stored key or id (never by traits), else nil (any
	// other value reads as nil). Older servers send no mark.
	Visitor map[string]interface{}
	Counts  map[string]interface{}
	// Network is the address as the risk engine saw it (never coordinates),
	// as the API sent it: countryCode, region, city, accuracyKm, timeZone,
	// asn, asnOrg, type (isp, hosting, tor, relay: Apple's iCloud Private
	// Relay, never a VPN or hosting; or unknown), tor, hosting,
	// hostingProvider, proxy (reported as a proxy in the last 30 days:
	// context; absent on older servers; the proxy list includes IP2Proxy
	// LITE data available from https://lite.ip2location.com),
	// timezoneMismatch. Newer servers also send the kind of network
	// (absent on older ones): kind (NetworkKinds, an open list: new values may
	// be added in minor versions), kindSource (address, network, mixed,
	// network_open or name), vpn (a VPN company's own address), shared (10 or
	// more browsers, or 5 or more accounts from 3 or more browsers, used the
	// identification's own address on your pages in 24 hours: context only),
	// sharedVisitors24h and sharedAccounts24h ("at least" counts: 1, 2, 5,
	// 10, 100 or 1000, as float64 like every JSON number) and
	// lookAlikeMatching (false: this computer was recognised only by its own
	// key, cookie or stored id, never because it looks like another one;
	// true: look-alike matching was allowed). Each is nil when not known:
	// kind, kindSource and vpn for an identification from before them; the
	// shared fields and lookAlikeMatching when not counted, or when ClientIP
	// was another address than the one the browser identified from
	// (sharedAccounts24h also with no account; lookAlikeMatching also when
	// not decided: phones, tablets and Safari).
	Network map[string]interface{}
	// Velocity holds the visitor's counts: accounts24h, accounts30d,
	// signUps24h, countries24h, idResets7d, identifications1h, identifications24h.
	Velocity map[string]interface{}
	// Bot is one answer to "a bot?": result (detected, suspected,
	// not_detected) and reasons, the detected ones first (webdriver,
	// headless, tool_<name> for each of tools, agent_verified), then the
	// suspected ones (pointer_synthetic, input_synthetic, agent_pace,
	// zero_window, headless_window, emulator, cdp: the DevTools protocol
	// attached, cdp_input: a press with no pressure, input_no_focus: a click
	// or key into a page that was not in front, insert_text_bulk: text with
	// no key pressed, scripted_click: a form sent with no click or key,
	// agent_unverified, agent_claimed), and soft_gpu next to another reason.
	// New reasons may be added in minor versions. Servers since 2026-11-24
	// also send (absent on older ones): type (ai_agent: an AI agent or bot by
	// its own identity or its marks on the page, or a pause before every
	// step; automation: a driven browser; script: moved or typed like
	// software in a browser that shows no driver; or nil), tools (whose
	// marks were on the page: the automation tools selenium, playwright,
	// puppeteer, phantomjs, nightmare and headless_chrome, and the AI agents
	// claude_agent (the Claude app's browser or Claude in Chrome),
	// comet_agent (Perplexity Comet), genspark_agent, browser_use, stagehand
	// and skyvern), agent (nil, or provider, name, category ai_agent |
	// ai_crawler | search_crawler, identity verified | unverified | claimed:
	// a Web Bot Auth signature checked against the provider's published
	// keys, or the user agent only) and input (insert_no_keys, uniform_keys,
	// instant_keys, center_press, agent_pace). The AI agents' tools and the
	// reasons cdp_input, input_no_focus, insert_text_bulk and scripted_click
	// come from servers since 2026-11-25.
	Bot map[string]interface{}
	// AccountDevice: did this account use the device before? nil before an account is named.
	AccountDevice *AccountDevice
	// Suspect is the suspect score in shadow; nil from servers that do not send it.
	Suspect *Suspect
	Signals []Signal
	// StepUp: ask for more on this page. Never a reason to refuse.
	StepUp bool
	// WouldStepUp: a signal that asks was raised, enforced or not.
	WouldStepUp bool
	// Requires is none, number_match or passkey.
	Requires string
	// Mode is enforce when at least one raised signal is enforced, else shadow.
	Mode string
	// Engine is the engine's state for this check; "unavailable" when the risk engine could not be reached and the verdict is a safe default (empty when the answer carries none).
	Engine string
	// CaseCode opens the decision record ("Why?") in the dashboard.
	CaseCode string
}

// ParseSuspect reads the suspect score of an answer, a GetEvent answer or a
// SearchEvents row (its "suspect" member): nil when it is not one.
func ParseSuspect(raw interface{}) *Suspect {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	score, ok := wholeNumber(m["score"])
	if !ok {
		return nil
	}
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}
	out := &Suspect{Score: score, Mode: "shadow", Reasons: []SuspectReason{}, WouldDo: "allow"}
	if b, _ := m["band"].(string); contains([]string{"low", "medium", "high", "critical"}, b) {
		out.Band = b
	} else {
		switch {
		case score >= 80:
			out.Band = "critical"
		case score >= 60:
			out.Band = "high"
		case score >= 30:
			out.Band = "medium"
		default:
			out.Band = "low"
		}
	}
	if w, _ := m["wouldDo"].(string); contains([]string{"allow", "number_match", "passkey", "block"}, w) {
		out.WouldDo = w
	}
	list, _ := m["reasons"].([]interface{})
	for _, r := range list {
		rm, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		code, ok := rm["code"].(string)
		if !ok {
			continue
		}
		points, _ := wholeNumber(rm["points"])
		by, _ := rm["by"].(string)
		if !contains([]string{"server", "site", "page", "brand"}, by) {
			by = "server"
		}
		text, _ := rm["text"].(string)
		out.Reasons = append(out.Reasons, SuspectReason{Code: code, Points: points, By: by, Text: text})
	}
	return out
}

// ParseAccountDevice reads the "accountDevice" member of an answer or a
// GetEvent answer: nil when it is not one.
func ParseAccountDevice(raw interface{}) *AccountDevice {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	status, _ := m["status"].(string)
	if !contains([]string{"known", "likely", "new", "first"}, status) {
		return nil
	}
	out := &AccountDevice{Status: status}
	out.VisitorID, _ = m["visitorId"].(string)
	out.Since, _ = m["since"].(string)
	return out
}

func wholeNumber(v interface{}) (int, bool) {
	f, ok := v.(float64)
	if !ok || f != float64(int(f)) {
		return 0, false
	}
	return int(f), true
}

// visitorOf is the visitor as it came; a mark other than trusted or step_up
// reads as nil (no mark applied). The answer's own map is never changed.
func visitorOf(raw interface{}) map[string]interface{} {
	v, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	mark, has := v["mark"]
	if !has || mark == nil || mark == "trusted" || mark == "step_up" {
		return v
	}
	out := make(map[string]interface{}, len(v))
	for k, x := range v {
		out[k] = x
	}
	out["mark"] = nil
	return out
}

// ParseCheck reads an answer, failing toward asking: StepUp is true unless
// it says exactly false; junk signals are dropped.
func ParseCheck(res map[string]interface{}) *CheckResult {
	out := &CheckResult{Report: "invalid", Signals: []Signal{}, StepUp: true, Requires: "none", Mode: "shadow"}
	if res == nil {
		return out
	}
	if r, _ := res["report"].(string); contains(Reports, r) {
		out.Report = r
	}
	out.RequestID, _ = res["requestId"].(string)
	out.VisitorID, _ = res["visitorId"].(string)
	out.Confidence, _ = res["confidence"].(float64)
	out.Visitor = visitorOf(res["visitor"])
	out.Counts, _ = res["counts"].(map[string]interface{})
	out.Network, _ = res["network"].(map[string]interface{})
	out.Velocity, _ = res["velocity"].(map[string]interface{})
	out.Bot, _ = res["bot"].(map[string]interface{})
	out.AccountDevice = ParseAccountDevice(res["accountDevice"])
	out.Suspect = ParseSuspect(res["suspect"])
	out.CaseCode, _ = res["caseCode"].(string)
	out.Engine, _ = res["engine"].(string)
	list, _ := res["signals"].([]interface{})
	for _, raw := range list {
		s, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		code, ok := s["code"].(string)
		if !ok {
			continue
		}
		text, _ := s["text"].(string)
		strength, _ := s["strength"].(string)
		if strength != "passkey" && strength != "none" {
			strength = "number_match"
		}
		evidence, _ := s["evidence"].(map[string]interface{})
		enforced, _ := s["enforced"].(bool)
		out.Signals = append(out.Signals, Signal{Code: code, Text: text, Strength: strength, Enforced: enforced, Evidence: evidence})
	}
	if v, ok := res["stepUp"].(bool); ok && !v {
		out.StepUp = false
	}
	out.WouldStepUp, _ = res["wouldStepUp"].(bool)
	if r, _ := res["requires"].(string); r == "number_match" || r == "passkey" {
		out.Requires = r
	}
	if m, _ := res["mode"].(string); m == "enforce" {
		out.Mode = "enforce"
	}
	return out
}

// Check checks the page's identification for an account: it binds it (one
// account per identification, 15 minutes) and asks the risk engine. Pass the
// form field as it came: empty or made up is still a verdict (Report missing,
// unknown), never an error. 409 device_risk_off until your workspace turns
// Device risk on.
//
//	r, err := dr.Check(ctx, devicerisk.CheckOptions{RequestID: req.FormValue("touchque_request_id"), Event: "sign_up", ExternalUsername: email, ClientIP: ip})
//	if err == nil && r.StepUp { askForEmailCode() } // never refuse on it alone
func (c *Client) Check(ctx context.Context, opts CheckOptions) (*CheckResult, error) {
	event := opts.Event
	if event == "" {
		event = "sign_in"
	}
	if !contains(CheckEvents, event) {
		return nil, &ConfigError{Message: "touchque: Check() Event must be one of " + strings.Join(CheckEvents, ", ")}
	}
	body := map[string]interface{}{"event": event}
	if opts.RequestID != "" {
		id := opts.RequestID
		if len(id) > 64 {
			id = id[:64]
		}
		body["requestId"] = id
	} else if opts.DeviceRisk != "" {
		body["deviceRisk"] = opts.DeviceRisk
	}
	if opts.ExternalUsername != "" {
		body["externalUsername"] = opts.ExternalUsername
	}
	if opts.ClientIP != "" {
		body["clientIp"] = opts.ClientIP
	}
	res, err := c.http.postCtx(ctx, "/device-risk/check", body)
	if err != nil {
		return nil, err
	}
	return ParseCheck(res), nil
}

// SearchOptions are SearchEvents' filters. From/To are YYYY-MM-DD (UTC) or
// ISO times (7 days before To by default, at most 90 days, within your
// retention). IP is an address or a CIDR range and is never returned. StepUp
// filters only when set. Cursor is the previous page's NextCursor, as it
// came. Limit is 1 to 100 (0: the default 25). Servers from before network
// kind ignore NetworkKind and Shared: the search is then not narrowed by them.
type SearchOptions struct {
	From, To, Signal, Kind, Origin, IP, Account, VisitorID, RequestID, Cursor string
	StepUp                                                                    *bool
	Limit                                                                     int
	// NetworkKind is the kind of network (one of NetworkKinds; Kind is the
	// page), sent as networkKind. It matches only identifications classified
	// since network kind exists: older ones have no kind. Sent as it is, so a
	// kind newer than this version works; one the server does not know is a
	// 400 invalid_network_kind.
	NetworkKind string
	// Shared filters only when set, sent as shared=true or shared=false:
	// true, identifications whose own address was shared (many browsers on
	// your pages in 24 hours); false, the ones counted and not shared. An
	// identification that was not counted matches neither.
	Shared *bool
}

// SearchResult is one page of SearchEvents: pass NextCursor back as Cursor
// until it is empty. Each event has no address and no raw trait; read its
// "suspect" with ParseSuspect, its "matchedBy" against MatchedBy and its
// "network" as CheckResult.Network describes it.
type SearchResult struct {
	Events     []map[string]interface{}
	NextCursor string
	From, To   string
}

// SearchEvents searches your workspace's identifications, newest first, one
// page at a time (GET /device-risk/events). Do not page by moving From/To. A
// search that would read too much is a 422 search_too_broad: narrow the range
// or add a filter.
func (c *Client) SearchEvents(ctx context.Context, opts SearchOptions) (*SearchResult, error) {
	if opts.Limit != 0 && (opts.Limit < 1 || opts.Limit > 100) {
		return nil, &ConfigError{Message: "touchque: SearchEvents() Limit must be 1 to 100"}
	}
	params := map[string]string{}
	for k, v := range map[string]string{"from": opts.From, "to": opts.To, "signal": opts.Signal, "kind": opts.Kind, "origin": opts.Origin,
		"ip": opts.IP, "account": opts.Account, "visitorId": opts.VisitorID, "requestId": opts.RequestID, "networkKind": opts.NetworkKind,
		"cursor": opts.Cursor} {
		if v != "" {
			params[k] = v
		}
	}
	if opts.StepUp != nil {
		params["stepUp"] = strconv.FormatBool(*opts.StepUp)
	}
	if opts.Shared != nil {
		params["shared"] = strconv.FormatBool(*opts.Shared)
	}
	if opts.Limit != 0 {
		params["limit"] = strconv.Itoa(opts.Limit)
	}
	res, err := c.http.getWithQueryCtx(ctx, "/device-risk/events", params)
	if err != nil {
		return nil, err
	}
	out := &SearchResult{Events: []map[string]interface{}{}}
	if list, ok := res["events"].([]interface{}); ok {
		for _, e := range list {
			if m, ok := e.(map[string]interface{}); ok {
				out.Events = append(out.Events, m)
			}
		}
	}
	out.NextCursor, _ = res["nextCursor"].(string)
	out.From, _ = res["from"].(string)
	out.To, _ = res["to"].(string)
	return out, nil
}

// GetEvent reads the trusted identification behind a requestId: the visitor
// (visitorId, confidence, matchedBy, mark: the mark actually applied, see
// CheckResult.Visitor), what the page showed (facts), the risk
// engine's verdict, accountDevice and suspect (read them with
// ParseAccountDevice and ParseSuspect). Read-only.
func (c *Client) GetEvent(ctx context.Context, requestID string) (map[string]interface{}, error) {
	if !requestIDPattern.MatchString(requestID) {
		return nil, &ConfigError{Message: "touchque: GetEvent() needs a requestId (dre_…)"}
	}
	return c.http.getWithQueryCtx(ctx, "/device-risk/events/"+url.PathEscape(requestID), nil)
}

// Card is a payment card as its BIN and last 4 digits only: never the card number.
type Card struct {
	// BIN is the first 6 to 8 digits.
	BIN string
	// Last4 is the last 4 digits.
	Last4 string
}

// ActivityOptions is what a visitor did that your server saw.
type ActivityOptions struct {
	// Type is one of ActivityTypes: payment_attempt, login_failed, not_found,
	// forbidden (with Path), otp_sent (with Phone), code_failed (a wrong
	// coupon or gift-card code). Required.
	Type string
	// RequestID is the page's identification (the touchque_request_id field as it came).
	RequestID string
	// VisitorID is the visitor (tqv_…), instead of RequestID.
	VisitorID string
	// ClientIP is the visitor's address (its network is counted); required
	// when neither id is known: a bot that never runs your page still counts.
	ClientIP string
	// ExternalUsername is the account it was for (at most 255 characters).
	ExternalUsername string
	// Outcome (payment_attempt) is what the payment provider answered: approved, declined or error.
	Outcome string
	// Card (payment_attempt) is the card's BIN and last 4 digits. Anything
	// else is refused before anything is sent.
	Card *Card
	// Phone (otp_sent) is the number the code went to: 6 to 15 digits, an optional leading +.
	Phone string
	// Path (not_found / forbidden) is the path asked for (only its class is counted; at most 2048 characters).
	Path string
}

// ActivityResult is the answer of Activity.
type ActivityResult struct {
	// Recorded is false when Touchque's counters are not reachable (nothing failed).
	Recorded bool
	// VisitorID is the visitor it was counted for, empty when only ClientIP named it.
	VisitorID string
	// PathClass (a not_found / forbidden path) is one of PathClasses, else empty.
	PathClass string
	// Signals are the abuse codes it raised (ActivitySignals): for 24 hours the
	// visitor's next identifications and checks carry them.
	Signals []string
}

const cardNumberRefused = "touchque: Activity() never send the card number: Card is BIN (6 to 8 digits) and Last4 (4 digits)"

// ActivityBody validates opts and returns the request body of Activity: a
// *ConfigError for a wrong field (nothing is sent).
func ActivityBody(opts ActivityOptions) (map[string]interface{}, error) {
	if !contains(ActivityTypes, opts.Type) {
		return nil, &ConfigError{Message: "touchque: Activity() Type must be one of " + strings.Join(ActivityTypes, ", ")}
	}
	body := map[string]interface{}{"type": opts.Type}
	for k, v := range map[string]string{"requestId": opts.RequestID, "visitorId": opts.VisitorID, "clientIp": opts.ClientIP,
		"externalUsername": opts.ExternalUsername, "phone": opts.Phone, "path": opts.Path} {
		if v != "" {
			body[k] = v
		}
	}
	if opts.RequestID == "" && opts.VisitorID == "" && opts.ClientIP == "" {
		return nil, &ConfigError{Message: "touchque: Activity() name the visitor: RequestID, VisitorID or ClientIP"}
	}
	if len(opts.ExternalUsername) > 255 {
		return nil, &ConfigError{Message: "touchque: Activity() ExternalUsername is at most 255 characters"}
	}
	if len(opts.Path) > 2048 {
		return nil, &ConfigError{Message: "touchque: Activity() Path is at most 2048 characters"}
	}
	if opts.Phone != "" && !phonePattern.MatchString(opts.Phone) {
		return nil, &ConfigError{Message: "touchque: Activity() Phone must be 6 to 15 digits, with an optional leading +"}
	}
	if opts.Outcome != "" {
		if !contains(ActivityOutcomes, opts.Outcome) {
			return nil, &ConfigError{Message: "touchque: Activity() Outcome must be one of " + strings.Join(ActivityOutcomes, ", ")}
		}
		body["outcome"] = opts.Outcome
	}
	if opts.Card != nil {
		if !binPattern.MatchString(opts.Card.BIN) || !last4Pattern.MatchString(opts.Card.Last4) {
			return nil, &ConfigError{Message: cardNumberRefused}
		}
		body["card"] = map[string]string{"bin": opts.Card.BIN, "last4": opts.Card.Last4}
	}
	return body, nil
}

// ParseActivity reads an Activity answer: Recorded only when it says exactly
// true; unknown path classes are dropped.
func ParseActivity(res map[string]interface{}) *ActivityResult {
	out := &ActivityResult{Signals: []string{}}
	out.Recorded, _ = res["recorded"].(bool)
	out.VisitorID, _ = res["visitorId"].(string)
	if p, _ := res["pathClass"].(string); contains(PathClasses, p) {
		out.PathClass = p
	}
	list, _ := res["signals"].([]interface{})
	for _, s := range list {
		if code, ok := s.(string); ok {
			out.Signals = append(out.Signals, code)
		}
	}
	return out
}

// Activity reports what a visitor did that your server saw (POST
// /device-risk/activity): payments, failed sign-ins, probing, SMS codes,
// wrong codes. Touchque counts it per visitor and per network and answers
// the abuse codes it raised; for 24 hours the visitor's next identifications
// and checks carry them (shadow: they decide nothing on their own).
//
//	a, err := dr.Activity(ctx, devicerisk.ActivityOptions{Type: "payment_attempt", RequestID: req.FormValue("touchque_request_id"),
//		ClientIP: ip, Outcome: "declined", Card: &devicerisk.Card{BIN: "411111", Last4: "1111"}})
//	if err == nil && slices.Contains(a.Signals, "abuse_card_testing") { stopTakingCards() }
//
// Never send a card number: a Card that is not exactly a BIN and the last 4
// digits is a *ConfigError, before anything is sent.
func (c *Client) Activity(ctx context.Context, opts ActivityOptions) (*ActivityResult, error) {
	body, err := ActivityBody(opts)
	if err != nil {
		return nil, err
	}
	res, err := c.http.postCtx(ctx, "/device-risk/activity", body)
	if err != nil {
		return nil, err
	}
	return ParseActivity(res), nil
}
