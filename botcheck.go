package devicerisk

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// BotResults are a bot check's answers to "a bot?".
var BotResults = []string{"detected", "suspected", "not_detected"}

// BotCategories are the kinds of bot a bot check names. New ones may be
// added: BotCheckBot.Category carries them as they came.
var BotCategories = []string{"ai_agent", "ai_assistant", "ai_crawler", "ai_search", "search_crawler", "link_preview", "seo",
	"monitoring", "archiver", "feed_reader", "security_scanner", "http_client", "headless_browser", "automation"}

// BotIdentities are whether a bot's name is proven: verified, unverified (a
// spoofed name) or claimed (no way to check it).
var BotIdentities = []string{"verified", "unverified", "claimed"}

// BotVerifiedBy are what proved a verified bot's name.
var BotVerifiedBy = []string{"signature", "ip_list", "reverse_dns", "asn"}

// BotConfidences are how sure a bot check is.
var BotConfidences = []string{"high", "medium", "low"}

// BotSuggestions are a bot check's advice, in shadow: Touchque never enforces it.
var BotSuggestions = []string{"allow", "block", "challenge"}

// BotCheckHTTPVersions are the values BotCheckRequest.HTTPVersion is sent as.
var BotCheckHTTPVersions = []string{"1.0", "1.1", "2", "3"}

// The API's limits (a browser sends 10 to 30 headers, a few KB in all).
const (
	botCheckMaxHeaders    = 100
	botCheckMaxNameChars  = 128
	botCheckMaxValueChars = 4096
	// 32 KB, kept a little under 32 KiB so either reading of the API's limit holds.
	botCheckMaxBodyBytes = 32000
	// A longer URL is left out, never cut: a signature may cover its path.
	botCheckMaxURLChars = 4096
	botCheckMaxJA4Chars = 128
)

// BotCheckBlankedHeaders go by name only, matched without case: credentials and
// session cookies never leave your server, while their place among the headers
// still counts.
var BotCheckBlankedHeaders = []string{"authorization", "cookie", "proxy-authorization", "x-api-key", "set-cookie"}

var blankedHeaders = func() map[string]bool {
	m := make(map[string]bool, len(BotCheckBlankedHeaders))
	for _, name := range BotCheckBlankedHeaders {
		m[name] = true
	}
	return m
}()

var (
	// The methods the API reads; anything else is left out.
	botCheckMethod = regexp.MustCompile(`^[A-Za-z]{1,16}$`)
	// A header name as HTTP allows it (RFC 9110 token).
	botCheckToken      = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")
	botCheckAuthority  = regexp.MustCompile(`^([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?)(?::([0-9]{0,5}))?$`)
	botCheckNumeric    = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]*)$`)
	botCheckDottedQuad = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`)
	botCheckVersions   = map[string]string{"1.0": "1.0", "1.1": "1.1", "2": "2", "2.0": "2", "h2": "2", "h2c": "2", "3": "3", "3.0": "3", "h3": "3"}
)

// BotCheckHeader is one header of the visitor's request.
type BotCheckHeader struct {
	Name  string
	Value string
}

// BotCheckTLS is what your edge (load balancer, CDN or TLS terminator) saw of
// the visitor's TLS handshake. Both are optional.
type BotCheckTLS struct {
	// Ciphers are the cipher suites the visitor offered, as your edge writes
	// them (for example nginx's $ssl_ciphers). A longer list is cut to 4096
	// characters.
	Ciphers string
	// JA4 is the visitor's JA4 TLS fingerprint, when your edge computes one
	// (one over 128 characters is not a JA4 and is left out).
	JA4 string
}

// BotCheckRequest is one request a visitor sent your server. Build it with
// BotCheckRequestFrom, or by hand when your edge gives you the headers in the
// order they arrived.
type BotCheckRequest struct {
	// IP is the visitor's IPv4 or IPv6 address, as your server saw it.
	// Required. A port ("203.0.113.7:51234", "[2001:db8::1]:443") and a zone
	// are dropped, and ::ffff:a.b.c.d goes as a.b.c.d.
	IP string
	// Headers are the request's headers, in the order they arrived when you
	// know it (the order is a sign too); empty for a request that had none.
	// Authorization, Cookie, Proxy-Authorization, X-Api-Key and Set-Cookie go
	// with empty values, their names kept for the order. What the visitor
	// sent never makes BotCheck fail: the first 100 headers go, a name is cut
	// to 128 characters and a value to 4096, the body is kept under 32 KB,
	// and the request tells Touchque it was cut ("truncated"). HTTP/2
	// pseudo-headers and headers HTTP does not allow are left out.
	Headers []BotCheckHeader
	// HeaderOrderUnknown says Headers are not in the order they arrived (Go's
	// net/http does not keep it): they go as a set, repeats of a name joined
	// with ", ", and Touchque reads no order into them. BotCheckRequestFrom
	// sets it.
	HeaderOrderUnknown bool
	// Method is the request's method (GET, POST…). Optional; one that is not
	// 1 to 16 letters is left out.
	Method string
	// URL is the URL or path asked for. Optional. Only its host and path are
	// sent: the query string, the fragment and any user:password are dropped
	// first, and Touchque stores none of it. A host Touchque could not read
	// goes as the path alone; one over 4096 characters is left out.
	URL string
	// HTTPVersion is the HTTP version the visitor spoke to your edge, only
	// when your edge tells you: 1.0, 1.1, 2 or 3 (HTTP/2.0 and h2 read as 2).
	// Anything else is left out. Never your server's own r.Proto: behind a
	// proxy that is the proxy's connection, not the visitor's.
	HTTPVersion string
	// TLS is what your edge saw of the visitor's handshake. Optional.
	TLS *BotCheckTLS
}

// BotCheckReason is one sign a bot check saw.
type BotCheckReason struct {
	// Code is the sign's stable code.
	Code string
	// Text says it in an English sentence your fraud team reads.
	Text string
}

// BotCheckBot is the answer to "which bot sent this, and is that proven?".
// Each field is what the API sent, values this version does not know
// included; empty means none.
type BotCheckBot struct {
	// Result is detected, suspected or not_detected (BotResults).
	// not_detected means no sign of a bot in this one request (also what an
	// answer that cannot be read says: "cannot tell" is never a bot); a page
	// that runs the tag tells more (Check).
	Result string
	// Category is the kind of bot (BotCategories): ai_agent, ai_assistant,
	// ai_crawler, ai_search, search_crawler, link_preview, seo, monitoring,
	// archiver, feed_reader, security_scanner, http_client,
	// headless_browser or automation. New ones may be added.
	Category string
	// Provider is who runs it, e.g. OpenAI.
	Provider string
	// Name is what it is called, e.g. ChatGPT-User.
	Name string
	// Identity is whether that name is proven (BotIdentities):
	//   - verified: its operator's signature, published addresses or reverse
	//     DNS proved it;
	//   - unverified: a spoofed name. Its operator publishes a way to check
	//     it, and that check failed;
	//   - claimed: its operator gives no way to check it, or Touchque cannot
	//     check it right now (never a guess).
	Identity string
	// VerifiedBy is what proved a verified name: signature, ip_list,
	// reverse_dns or asn (BotVerifiedBy).
	VerifiedBy string
	// Confidence is high, medium or low (BotConfidences).
	Confidence string
	// Rule is the stable id of the rule that decided, e.g.
	// directory.chatgpt_user, http_client.curl or
	// browser.chromium_without_client_hints.
	Rule string
	// Reasons are every sign seen, each with a sentence for your fraud team.
	Reasons []BotCheckReason
}

// BotCheckNetwork is the visitor's network, from Touchque's own data.
type BotCheckNetwork struct {
	// ASN is the network's autonomous system number (0 when unknown).
	ASN int
	// ASNOrg is the organization that runs it.
	ASNOrg string
	// CountryCode is the address's two-letter country code.
	CountryCode string
	// Hosting means a cloud or hosting network, not a home or mobile one
	// (false also when unknown: Raw["network"] tells the two apart).
	Hosting bool
}

// BotCheckResult is the answer of BotCheck.
type BotCheckResult struct {
	Bot BotCheckBot
	// Network is nil when Touchque cannot tell.
	Network *BotCheckNetwork
	// Suggestion is advice in shadow: Touchque never enforces it, your server
	// decides (BotSuggestions). An answer that cannot be read says allow.
	//   - allow: a verified bot, a declared crawler, assistant or other bot that
	//     cannot be checked, or no bot;
	//   - block: a spoofed name (Identity unverified, or a failed signature);
	//   - challenge: an AI agent that only names itself (it acts for a person:
	//     ask that person), undeclared automation (an HTTP client, a headless
	//     browser, a browser whose claims contradict each other) or a suspected bot.
	Suggestion string
	// RulesVersion is the version of the rules that answered, e.g. 2026.11.25-1.
	RulesVersion string
	// Raw is the whole answer as it came, with any fields this version does not know.
	Raw map[string]interface{}
}

// botCheckField is one header as it goes.
type botCheckField struct{ name, value string }

// BotCheckBody returns the request body of BotCheck: its headers are
// [][2]string pairs in order, or a map[string]string when the order is
// unknown, with the sensitive values blank, whoever built req. What the
// visitor sent never makes it fail; a *ConfigError is only for what your code
// passed wrong (no IP, a header without a name), and nothing is sent.
func BotCheckBody(req BotCheckRequest) (map[string]interface{}, error) {
	ip := botCheckIP(req.IP)
	if ip == "" {
		return nil, &ConfigError{Message: "touchque: BotCheck() needs the visitor's IP: an IPv4 or IPv6 address"}
	}
	fields, truncated, err := botCheckFields(req.Headers, req.HeaderOrderUnknown)
	if err != nil {
		return nil, err
	}
	method := strings.TrimSpace(req.Method)
	if !botCheckMethod.MatchString(method) {
		method = ""
	}
	u := botCheckURL(req.URL)
	version := botCheckVersions[strings.TrimPrefix(strings.ToLower(strings.TrimSpace(req.HTTPVersion)), "http/")]
	tls := map[string]string{}
	if req.TLS != nil {
		if c := strings.TrimSpace(req.TLS.Ciphers); c != "" {
			tls["ciphers"] = cutChars(c, botCheckMaxValueChars) // the list the visitor offered can be long
		}
		if j := strings.TrimSpace(req.TLS.JA4); j != "" && cutChars(j, botCheckMaxJA4Chars) == j {
			tls["ja4"] = j
		}
	}

	// drop: 1 leaves out tls, 2 also the url.
	build := func(count, limit, drop int) (map[string]interface{}, int) {
		cut := truncated || count < len(fields)
		var headers interface{}
		if req.HeaderOrderUnknown {
			set := make(map[string]string, count)
			for _, f := range fields[:count] {
				v := cutChars(f.value, limit)
				cut = cut || len(v) < len(f.value)
				set[f.name] = v
			}
			headers = set
		} else {
			pairs := make([][2]string, 0, count)
			for _, f := range fields[:count] {
				v := cutChars(f.value, limit)
				cut = cut || len(v) < len(f.value)
				pairs = append(pairs, [2]string{f.name, v})
			}
			headers = pairs
		}
		body := map[string]interface{}{"ip": ip, "headers": headers}
		if method != "" {
			body["method"] = method
		}
		if u != "" && drop < 2 {
			body["url"] = u
		}
		if version != "" {
			body["httpVersion"] = version
		}
		if len(tls) > 0 && drop < 1 {
			body["tls"] = tls
		}
		if cut {
			body["truncated"] = true
		}
		raw, _ := json.Marshal(body) // exactly what postCtx sends
		return body, len(raw)
	}

	// Only an abnormal request needs fitting: the longest values are cut to one
	// length, the longest that fits. Names always fit (100 of 128 characters);
	// only a url or cipher list made long by escaping can crowd them out, so
	// tls goes first, then the url, and the last headers only after that.
	body, size := build(len(fields), botCheckMaxValueChars, 0)
	if size <= botCheckMaxBodyBytes {
		return body, nil
	}
	drop := 0
	for drop < 2 {
		if _, s := build(len(fields), 0, drop); s <= botCheckMaxBodyBytes {
			break
		}
		drop++
	}
	low, high := 0, botCheckMaxValueChars-1
	for low < high {
		mid := (low + high + 1) / 2
		if _, s := build(len(fields), mid, drop); s <= botCheckMaxBodyBytes {
			low = mid
		} else {
			high = mid - 1
		}
	}
	count := len(fields)
	body, size = build(count, low, drop)
	for size > botCheckMaxBodyBytes && count > 0 {
		count--
		body, size = build(count, 0, drop)
	}
	return body, nil
}

// botCheckIP is the visitor's address without a port, brackets or a zone, as
// the API reads it (::ffff:a.b.c.d as a.b.c.d), or "" when it is not an IP
// address.
func botCheckIP(raw string) string {
	ip := strings.TrimSpace(raw)
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	} else if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
		ip = ip[1 : len(ip)-1]
	}
	// A zone (fe80::1%eth0) means nothing outside your host.
	if i := strings.IndexByte(ip, '%'); i >= 0 {
		ip = ip[:i]
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

// botCheckFields are the headers as they go: HTTP/2 pseudo-headers left out
// (method and URL carry them, and :path has the query), and a header HTTP does
// not allow (a name that is not a token, a line break or NUL in the value), on
// which the API would refuse the whole check; repeats joined when the order is
// unknown; the first 100 kept; names and values cut to the API's limits; the
// sensitive values blank. truncated says a header was left out or cut.
func botCheckFields(list []BotCheckHeader, orderUnknown bool) ([]botCheckField, bool, error) {
	fields := make([]botCheckField, 0, len(list))
	seen := map[string]int{}
	truncated := false
	for _, h := range list {
		if h.Name == "" {
			return nil, false, &ConfigError{Message: "touchque: BotCheck() a header has no name"}
		}
		if strings.HasPrefix(h.Name, ":") {
			continue
		}
		if !botCheckToken.MatchString(h.Name) || strings.ContainsAny(h.Value, "\r\n\x00") {
			truncated = true
			continue
		}
		key := strings.ToLower(h.Name)
		if i, ok := seen[key]; ok && orderUnknown {
			fields[i].value += ", " + h.Value
			continue
		}
		seen[key] = len(fields)
		fields = append(fields, botCheckField{name: h.Name, value: h.Value})
	}
	if len(fields) > botCheckMaxHeaders {
		// More is not a browser; the rest is left out, never an error.
		fields, truncated = fields[:botCheckMaxHeaders], true
	}
	for i := range fields {
		f := &fields[i]
		if blankedHeaders[strings.ToLower(f.name)] {
			f.value = ""
		} else if v := cutChars(f.value, botCheckMaxValueChars); v != f.value {
			f.value, truncated = v, true
		}
		if n := cutChars(f.name, botCheckMaxNameChars); n != f.name {
			f.name, truncated = n, true
		}
	}
	return fields, truncated, nil
}

// cutChars keeps at most max characters as the API counts them (UTF-16 code
// units, as JavaScript does), never splitting one.
func cutChars(s string, max int) string {
	if len(s) <= max {
		return s // UTF-16 units never outnumber UTF-8 bytes
	}
	units := 0
	for i, r := range s {
		n := 1
		if r > 0xFFFF {
			n = 2
		}
		if units+n > max {
			return s[:i]
		}
		units += n
	}
	return s
}

// botCheckURL keeps a URL's host and path: its query string, fragment and any
// user:password never leave your server. A path, or an http(s) URL (ws and
// wss read as http and https); anything else, or one over 4096 characters, is
// left out.
func botCheckURL(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	var out string
	if strings.HasPrefix(s, "/") {
		out = s
	} else {
		sep := strings.Index(s, "://")
		if sep <= 0 {
			return ""
		}
		scheme := strings.ToLower(s[:sep])
		switch scheme {
		case "ws":
			scheme = "http"
		case "wss":
			scheme = "https"
		case "http", "https":
		default:
			return ""
		}
		authority, path := s[sep+3:], ""
		if i := strings.IndexByte(authority, '/'); i >= 0 {
			authority, path = authority[:i], authority[i:]
		}
		if i := strings.LastIndexByte(authority, '@'); i >= 0 {
			authority = authority[i+1:]
		}
		switch {
		case plainHost(authority):
			out = scheme + "://" + authority + path
		case path != "":
			out = path
		default:
			out = "/"
		}
	}
	if cutChars(out, botCheckMaxURLChars) != out {
		return ""
	}
	return out
}

// plainHost is a host Touchque reads as it is: letters, digits, dots, hyphens
// and underscores, an IPv4 address, a port up to 65535. Anything else (the
// Host header is the visitor's) goes as the path alone, so an odd Host never
// makes the API refuse the check.
func plainHost(authority string) bool {
	m := botCheckAuthority.FindStringSubmatch(authority)
	if m == nil {
		return false
	}
	if m[2] != "" {
		if port, err := strconv.Atoi(m[2]); err != nil || port > 65535 {
			return false
		}
	}
	host := strings.TrimSuffix(m[1], ".")
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if len(l) >= 4 && strings.EqualFold(l[:4], "xn--") {
			return false
		}
	}
	// A name that ends in a number is read as an IPv4 address: it must be one.
	if botCheckNumeric.MatchString(strings.ToLower(labels[len(labels)-1])) {
		return botCheckDottedQuad.MatchString(host)
	}
	return true
}

// BotCheckRequestFrom builds the BotCheckRequest of a request your handler
// received. clientIP is the visitor's address as your proxy or load balancer
// reports it; empty, it is the connection's own address (r.RemoteAddr). Take
// it from X-Forwarded-For only when your own proxy sets that header.
//
// Go's net/http keeps neither the order the headers arrived in nor, over
// HTTP/1, the case of their names, so they go as a set (HeaderOrderUnknown)
// and Touchque reads no order into them. HTTP/2 and 3 names go in lower
// case, as on the wire. Host (HTTP/1) and Transfer-Encoding, which net/http
// moves out of r.Header, are put back. Sensitive values are blank already,
// and the body is never read. HTTPVersion and TLS stay empty: r.Proto is the
// connection to your server (behind a proxy, the proxy's); set them only from
// what your edge saw.
func BotCheckRequestFrom(r *http.Request, clientIP string) BotCheckRequest {
	out := BotCheckRequest{IP: strings.TrimSpace(clientIP), HeaderOrderUnknown: true}
	if r == nil {
		return out
	}
	if out.IP == "" {
		out.IP = r.RemoteAddr
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			out.IP = host
		}
	}
	// HTTP/2 and 3 carry the host as :authority, never as a Host header.
	http1 := r.ProtoMajor < 2
	if http1 && r.Host != "" {
		out.Headers = append(out.Headers, BotCheckHeader{Name: "Host", Value: r.Host})
	}
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if http1 && r.Host != "" && strings.EqualFold(name, "Host") {
			continue
		}
		value := ""
		if !blankedHeaders[strings.ToLower(name)] {
			value = strings.Join(r.Header[name], ", ")
		}
		if !http1 {
			name = strings.ToLower(name)
		}
		out.Headers = append(out.Headers, BotCheckHeader{Name: name, Value: value})
	}
	if http1 && len(r.TransferEncoding) > 0 {
		out.Headers = append(out.Headers, BotCheckHeader{Name: "Transfer-Encoding", Value: strings.Join(r.TransferEncoding, ", ")})
	}
	out.Method = r.Method
	out.URL = requestURL(r)
	return out
}

// requestURL is the host and path the visitor asked for, never the query.
func requestURL(r *http.Request) string {
	if r.URL == nil {
		return ""
	}
	u := url.URL{Path: r.URL.Path, RawPath: r.URL.RawPath}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if host != "" {
		u.Scheme, u.Host = "http", host
		if r.TLS != nil {
			u.Scheme = "https"
		}
	}
	return u.String()
}

// ParseBotCheck reads a BotCheck answer without failing on what it does not
// know: unknown values come through as they came, unknown fields stay in Raw,
// and reasons without a code are dropped. What it cannot read is "cannot
// tell": Result not_detected and Suggestion allow, never a block.
func ParseBotCheck(res map[string]interface{}) *BotCheckResult {
	out := &BotCheckResult{Bot: BotCheckBot{Reasons: []BotCheckReason{}}, Raw: res}
	if bot, ok := res["bot"].(map[string]interface{}); ok {
		b := &out.Bot
		b.Result, _ = bot["result"].(string)
		b.Category, _ = bot["category"].(string)
		b.Provider, _ = bot["provider"].(string)
		b.Name, _ = bot["name"].(string)
		b.Identity, _ = bot["identity"].(string)
		b.VerifiedBy, _ = bot["verifiedBy"].(string)
		b.Confidence, _ = bot["confidence"].(string)
		b.Rule, _ = bot["rule"].(string)
		list, _ := bot["reasons"].([]interface{})
		for _, raw := range list {
			m, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			code, _ := m["code"].(string)
			if code == "" {
				continue
			}
			text, _ := m["text"].(string)
			b.Reasons = append(b.Reasons, BotCheckReason{Code: code, Text: text})
		}
	}
	if out.Bot.Result == "" {
		out.Bot.Result = "not_detected"
	}
	if n, ok := res["network"].(map[string]interface{}); ok {
		network := &BotCheckNetwork{}
		if asn, ok := wholeNumber(n["asn"]); ok && asn > 0 {
			network.ASN = asn
		}
		network.ASNOrg, _ = n["asnOrg"].(string)
		network.CountryCode, _ = n["countryCode"].(string)
		network.Hosting, _ = n["hosting"].(bool)
		out.Network = network
	}
	out.Suggestion, _ = res["suggestion"].(string)
	if out.Suggestion == "" {
		out.Suggestion = "allow"
	}
	out.RulesVersion, _ = res["rulesVersion"].(string)
	return out
}

// BotCheck asks which bot sent one request your server received (POST
// /device-risk/bot-check), for the visitors that never run your page's tag:
// ChatGPT-User, GPTBot, Meta's crawlers, curl and scripts. It sends the
// visitor's IP and headers. Touchque answers on its own servers, with no
// third-party service at request time (the bot operators' own published
// address lists and signing keys, fetched ahead of time, reverse DNS and its
// own network data), and keeps nothing but short-lived keyed-hash counters.
//
//	b, err := dr.BotCheck(ctx, devicerisk.BotCheckRequestFrom(req, ip))
//	if err == nil && b.Suggestion == "block" { logSpoofedBot(b.Bot.Name) } // a spoofed name; advice in shadow
//
// Authorization, Cookie, Proxy-Authorization, X-Api-Key and Set-Cookie go
// with empty values, and the URL without its query string. What the visitor
// sent never makes it fail: past 100 headers, long names or values, or over
// 32 KB, the request is kept to the API's limits and says it was cut. No IP
// is a *ConfigError before anything is sent. 409 device_risk_off until your
// workspace turns Device risk on; 429 (RetryAfter) past your workspace's
// bot-check budget.
func (c *Client) BotCheck(ctx context.Context, req BotCheckRequest) (*BotCheckResult, error) {
	body, err := BotCheckBody(req)
	if err != nil {
		return nil, err
	}
	res, err := c.http.postCtx(ctx, "/device-risk/bot-check", body)
	if err != nil {
		return nil, err
	}
	return ParseBotCheck(res), nil
}
