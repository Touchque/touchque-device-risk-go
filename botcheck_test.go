package devicerisk

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// BotCheck against a local fake Touchque (httptest, no network): the request
// as it leaves, credentials blanked, the order kept, the limits, the answer.

type botCheckCall struct {
	method, path string
	header       http.Header
	body         []byte
}

// fakeBotCheckAPI answers every call with status, header and answer, and keeps what it received.
func fakeBotCheckAPI(t *testing.T, status int, header http.Header, answer string) (*Client, func() []botCheckCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []botCheckCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, botCheckCall{method: r.Method, path: r.URL.RequestURI(), header: r.Header.Clone(), body: body})
		mu.Unlock()
		for k, v := range header {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(srv.Close)
	return NewClient(testConfig(srv.URL)), func() []botCheckCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]botCheckCall(nil), calls...)
	}
}

// signatureOf is the signature the API expects for a call (testConfig's secret).
func signatureOf(c botCheckCall) string {
	sum := sha256.Sum256(c.body)
	mac := hmac.New(sha256.New, []byte("shh"))
	mac.Write([]byte(c.method + ":" + c.path + ":" + c.header.Get("x-timestamp") + ":" + c.header.Get("x-nonce") + ":" + hex.EncodeToString(sum[:])))
	return hex.EncodeToString(mac.Sum(nil))
}

func sentBody(t *testing.T, c botCheckCall) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(c.body, &m); err != nil {
		t.Fatalf("body %q: %v", c.body, err)
	}
	return m
}

func oneCall(t *testing.T, calls func() []botCheckCall) botCheckCall {
	t.Helper()
	got := calls()
	if len(got) != 1 {
		t.Fatalf("%d calls were sent, want 1", len(got))
	}
	return got[0]
}

const chatGPTUserAnswer = `{"bot":{"result":"detected","category":"ai_assistant","provider":"OpenAI","name":"ChatGPT-User",
	"identity":"verified","verifiedBy":"ip_list","confidence":"high","rule":"directory.chatgpt_user","reasons":[
	{"code":"ua_names_bot","text":"The user agent names ChatGPT-User."},
	{"code":"ip_in_operator_list","text":"The address is in OpenAI's published list for ChatGPT-User."}]},
	"network":{"asn":8075,"asnOrg":"Microsoft Corporation","countryCode":"US","hosting":true},
	"suggestion":"allow","rulesVersion":"2026.11.25-1"}`

func TestBotCheckSendsTheRequestSignedAndReadsTheAnswer(t *testing.T) {
	dr, calls := fakeBotCheckAPI(t, 200, nil, chatGPTUserAnswer)
	ua := "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"
	ciphers, ja4 := "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384", "t13d1516h2_8daaf6152771_02713d6af862"
	b, err := dr.BotCheck(context.Background(), BotCheckRequest{
		IP:          "203.0.113.7",
		Headers:     []BotCheckHeader{{"Host", "shop.example.com"}, {"User-Agent", ua}, {"Accept", "*/*"}},
		Method:      "GET",
		URL:         "https://user:pass@shop.example.com/pricing?coupon=SECRET#plans",
		HTTPVersion: "1.1",
		TLS:         &BotCheckTLS{Ciphers: ciphers, JA4: ja4},
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.Raw["rulesVersion"] != "2026.11.25-1" {
		t.Fatalf("raw: %v", b.Raw)
	}
	b.Raw = nil
	want := &BotCheckResult{
		Bot: BotCheckBot{Result: "detected", Category: "ai_assistant", Provider: "OpenAI", Name: "ChatGPT-User", Identity: "verified",
			VerifiedBy: "ip_list", Confidence: "high", Rule: "directory.chatgpt_user", Reasons: []BotCheckReason{
				{Code: "ua_names_bot", Text: "The user agent names ChatGPT-User."},
				{Code: "ip_in_operator_list", Text: "The address is in OpenAI's published list for ChatGPT-User."},
			}},
		Network:    &BotCheckNetwork{ASN: 8075, ASNOrg: "Microsoft Corporation", CountryCode: "US", Hosting: true},
		Suggestion: "allow", RulesVersion: "2026.11.25-1",
	}
	if !reflect.DeepEqual(b, want) {
		t.Fatalf("answer: %+v", b)
	}

	c := oneCall(t, calls)
	if c.method != "POST" || c.path != "/device-risk/bot-check" {
		t.Fatalf("call: %s %s", c.method, c.path)
	}
	if c.header.Get("x-api-key") != "tq_auth_test123" || c.header.Get("x-signature") != signatureOf(c) {
		t.Fatal("not signed like the other partner calls")
	}
	wantBody := map[string]interface{}{
		"ip":          "203.0.113.7",
		"headers":     []interface{}{[]interface{}{"Host", "shop.example.com"}, []interface{}{"User-Agent", ua}, []interface{}{"Accept", "*/*"}},
		"method":      "GET",
		"url":         "https://shop.example.com/pricing",
		"httpVersion": "1.1",
		"tls":         map[string]interface{}{"ciphers": ciphers, "ja4": ja4},
	}
	if got := sentBody(t, c); !reflect.DeepEqual(got, wantBody) {
		t.Fatalf("body: %v", got)
	}
	if s := string(c.body); strings.Contains(s, "SECRET") || strings.Contains(s, "pass") {
		t.Fatalf("the query string or the URL's password left the server: %s", s)
	}
}

func TestBotCheckBlanksCredentialsAndKeepsTheOrder(t *testing.T) {
	dr, calls := fakeBotCheckAPI(t, 200, nil, `{"bot":{"result":"detected","category":"http_client","rule":"http_client.curl"},"suggestion":"challenge"}`)
	_, err := dr.BotCheck(context.Background(), BotCheckRequest{IP: "203.0.113.7", Headers: []BotCheckHeader{
		{"Host", "shop.example.com"}, {"cookie", "sid=SECRET-1"}, {"User-Agent", "curl/8.7.1"}, {"Authorization", "Bearer SECRET-2"},
		{"Accept", "*/*"}, {"PROXY-AUTHORIZATION", "Basic SECRET-3"}, {"X-Api-Key", "SECRET-4"}, {"Set-Cookie", "a=SECRET-5"},
		{"Accept", "text/html"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := oneCall(t, calls)
	want := []interface{}{
		[]interface{}{"Host", "shop.example.com"}, []interface{}{"cookie", ""}, []interface{}{"User-Agent", "curl/8.7.1"},
		[]interface{}{"Authorization", ""}, []interface{}{"Accept", "*/*"}, []interface{}{"PROXY-AUTHORIZATION", ""},
		[]interface{}{"X-Api-Key", ""}, []interface{}{"Set-Cookie", ""}, []interface{}{"Accept", "text/html"},
	}
	if got := sentBody(t, c)["headers"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("headers: %v", got)
	}
	if strings.Contains(string(c.body), "SECRET") {
		t.Fatalf("a credential left the server: %s", c.body)
	}
}

func TestBotCheckRequestFromAGoRequest(t *testing.T) {
	chrome := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	r := httptest.NewRequest("POST", "https://shop.example.com/login?next=%2Fcart&token=SECRET-0", nil)
	r.RemoteAddr = "198.51.100.23:51234"
	r.Header.Set("User-Agent", chrome)
	r.Header.Add("Accept", "text/html")
	r.Header.Add("Accept", "application/xhtml+xml")
	r.Header.Set("Sec-Ch-Ua", `"Chromium";v="131"`)
	r.Header.Set("Cookie", "sid=SECRET-1")
	r.Header.Set("Authorization", "Bearer SECRET-2")
	r.TransferEncoding = []string{"chunked"}

	req := BotCheckRequestFrom(r, "")
	// No HTTPVersion: r.Proto is the connection to this server (behind a proxy, the proxy's).
	if req.IP != "198.51.100.23" || !req.HeaderOrderUnknown || req.Method != "POST" || req.HTTPVersion != "" ||
		req.URL != "https://shop.example.com/login" || req.Headers[0] != (BotCheckHeader{"Host", "shop.example.com"}) {
		t.Fatalf("request: %+v", req)
	}
	if s := fmt.Sprintf("%+v", req); strings.Contains(s, "SECRET") {
		t.Fatalf("the request holds a credential: %s", s)
	}
	if ip := BotCheckRequestFrom(r, " 203.0.113.9 ").IP; ip != "203.0.113.9" {
		t.Fatalf("clientIP: %q", ip)
	}

	dr, calls := fakeBotCheckAPI(t, 200, nil, `{"bot":{"result":"not_detected","reasons":[]},"network":null,"suggestion":"allow","rulesVersion":"2026.11.25-1"}`)
	b, err := dr.BotCheck(context.Background(), req)
	if err != nil || b.Bot.Result != "not_detected" || b.Network != nil || b.Suggestion != "allow" {
		t.Fatalf("answer: %+v %v", b, err)
	}
	c := oneCall(t, calls)
	body := sentBody(t, c)
	// net/http keeps no order: the headers go as a set, repeats joined.
	wantHeaders := map[string]interface{}{"Host": "shop.example.com", "User-Agent": chrome, "Accept": "text/html, application/xhtml+xml",
		"Sec-Ch-Ua": `"Chromium";v="131"`, "Cookie": "", "Authorization": "", "Transfer-Encoding": "chunked"}
	if !reflect.DeepEqual(body["headers"], wantHeaders) || body["url"] != "https://shop.example.com/login" || body["ip"] != "198.51.100.23" {
		t.Fatalf("body: %v", body)
	}
	if strings.Contains(string(c.body), "SECRET") {
		t.Fatalf("a credential or the query left the server: %s", c.body)
	}
}

func TestBotCheckRequestFromHTTP2AndNoRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "https://shop.example.com/pricing", nil)
	r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/2.0", 2, 0
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	req := BotCheckRequestFrom(r, "2001:db8::7")
	// The host was :authority, not a header; HTTP/2 names are lower case on the wire.
	want := []BotCheckHeader{{"sec-fetch-mode", "navigate"}, {"user-agent", "Mozilla/5.0"}}
	if !reflect.DeepEqual(req.Headers, want) || req.HTTPVersion != "" || req.URL != "https://shop.example.com/pricing" || req.IP != "2001:db8::7" {
		t.Fatalf("HTTP/2: %+v", req)
	}

	none := BotCheckRequestFrom(nil, "203.0.113.7")
	body, err := BotCheckBody(none)
	if err != nil || none.IP != "203.0.113.7" || len(none.Headers) != 0 {
		t.Fatalf("no request: %+v %v", none, err)
	}
	if raw, _ := json.Marshal(body); !strings.Contains(string(raw), `"headers":{}`) {
		t.Fatalf("headers must go as an empty set, never null: %s", raw)
	}
	if raw, _ := json.Marshal(mustBody(t, BotCheckRequest{IP: "203.0.113.7"})); !strings.Contains(string(raw), `"headers":[]`) {
		t.Fatalf("headers must go as an empty list, never null: %s", raw)
	}
}

func mustBody(t *testing.T, req BotCheckRequest) map[string]interface{} {
	t.Helper()
	body, err := BotCheckBody(req)
	if err != nil {
		t.Fatalf("%+v: %v", req, err)
	}
	return body
}

func headersNamed(n int) []BotCheckHeader {
	out := make([]BotCheckHeader, n)
	for i := range out {
		out[i] = BotCheckHeader{Name: fmt.Sprintf("X-Header-%d", i), Value: "v"}
	}
	return out
}

func TestBotCheckOnlyYourCodesMistakesAreErrors(t *testing.T) {
	dr, calls := fakeBotCheckAPI(t, 200, nil, `{}`)
	for name, req := range map[string]BotCheckRequest{
		"no IP":         {Headers: headersNamed(1)},
		"a blank IP":    {IP: "  ", Headers: headersNamed(1)},
		"a host name":   {IP: "shop.example.com", Headers: headersNamed(1)},
		"an empty name": {IP: "203.0.113.7", Headers: []BotCheckHeader{{"", "v"}}},
	} {
		var cfg *ConfigError
		if _, err := dr.BotCheck(context.Background(), req); !errors.As(err, &cfg) || !strings.HasPrefix(cfg.Message, "touchque: BotCheck() ") {
			t.Fatalf("%s: want a *ConfigError, got %v", name, err)
		}
	}
	if n := len(calls()); n != 0 {
		t.Fatalf("%d calls were sent", n)
	}
	for in, want := range map[string]string{"203.0.113.7:51234": "203.0.113.7", "[2001:db8::1]": "2001:db8::1", " 2001:db8::1 ": "2001:db8::1",
		"::ffff:203.0.113.7": "203.0.113.7", "fe80::1%eth0": "fe80::1", "[fe80::1%eth0]:443": "fe80::1"} {
		if got := botCheckIP(in); got != want {
			t.Fatalf("ip %q: %q", in, got)
		}
	}
}

func TestBotCheckKeepsWhatTheVisitorSentToTheLimitsAndNeverFails(t *testing.T) {
	// Past 100 headers: the first 100 in order, and Touchque is told ("truncated").
	body := mustBody(t, BotCheckRequest{IP: "203.0.113.7", Headers: headersNamed(150)})
	pairs := body["headers"].([][2]string)
	if len(pairs) != 100 || pairs[99][0] != "X-Header-99" || body["truncated"] != true {
		t.Fatalf("150 headers: %d sent, truncated %v", len(pairs), body["truncated"])
	}
	// Exactly 100, and pseudo-headers, which never count: nothing cut.
	body = mustBody(t, BotCheckRequest{IP: "203.0.113.7", Headers: append([]BotCheckHeader{{":path", "/?q=1"}}, headersNamed(100)...)})
	if len(body["headers"].([][2]string)) != 100 || body["truncated"] != nil {
		t.Fatalf("100 headers: %v", body["truncated"])
	}
	// A name over 128 characters and a value over 4096 are cut; a blanked secret is not a cut.
	body = mustBody(t, BotCheckRequest{IP: "203.0.113.7", Headers: []BotCheckHeader{{strings.Repeat("x", 129), strings.Repeat("a", 5000)}, {"Cookie", strings.Repeat("c", 5000)}}})
	pairs = body["headers"].([][2]string)
	if len(pairs[0][0]) != 128 || len(pairs[0][1]) != 4096 || pairs[1][1] != "" || body["truncated"] != true {
		t.Fatalf("cut: %d, %d, %q, %v", len(pairs[0][0]), len(pairs[0][1]), pairs[1][1], body["truncated"])
	}
	if b := mustBody(t, BotCheckRequest{IP: "203.0.113.7", Headers: []BotCheckHeader{{"Cookie", strings.Repeat("c", 5000)}}}); b["truncated"] != nil {
		t.Fatal("a blanked secret read as a cut")
	}
	// Over 32 KB: the long values are cut to one length, the longest that fits; short ones stay whole.
	big := append([]BotCheckHeader{{"User-Agent", "curl/8.7.1"}}, make([]BotCheckHeader, 20)...)
	for i := 1; i < len(big); i++ {
		big[i] = BotCheckHeader{Name: fmt.Sprintf("X-Big-%d", i), Value: strings.Repeat("b", 4096)}
	}
	dr, calls := fakeBotCheckAPI(t, 200, nil, `{}`)
	if _, err := dr.BotCheck(context.Background(), BotCheckRequest{IP: "203.0.113.7", Headers: big}); err != nil {
		t.Fatal(err)
	}
	c := oneCall(t, calls)
	sent := sentBody(t, c)
	list := sent["headers"].([]interface{})
	lengths := map[int]bool{}
	for _, p := range list[1:] {
		lengths[len(p.([]interface{})[1].(string))] = true
	}
	if len(c.body) > 32000 || len(list) != 21 || list[0].([]interface{})[1] != "curl/8.7.1" || len(lengths) != 1 || lengths[4096] || sent["truncated"] != true {
		t.Fatalf("over 32 KB: %d bytes, %d headers, lengths %v", len(c.body), len(list), lengths)
	}
	// A long url and cipher list leave less room: every name stays, the values shrink, tls goes before any header.
	names := make([]BotCheckHeader, 100)
	for i := range names {
		names[i] = BotCheckHeader{Name: fmt.Sprintf("%03d%s", i, strings.Repeat("n", 125)), Value: strings.Repeat("v", 100)}
	}
	u := "https://shop.example.com/" + strings.Repeat("€", 4000)
	body = mustBody(t, BotCheckRequest{IP: "203.0.113.7", Headers: names, URL: u, TLS: &BotCheckTLS{Ciphers: strings.Repeat("€", 5000)}})
	raw, _ := json.Marshal(body)
	pairs = body["headers"].([][2]string)
	if len(raw) > 32000 || body["url"] != u || body["tls"] != nil || len(pairs) != 100 || len(pairs[0][1]) == 0 || len(pairs[0][1]) >= 100 {
		t.Fatalf("crowded: %d bytes, url kept %v, tls %v, %d headers", len(raw), body["url"] == u, body["tls"], len(pairs))
	}
	// Headers HTTP does not allow are left out (the API would refuse the whole check), and none at all go as [].
	body = mustBody(t, BotCheckRequest{IP: "203.0.113.7", Headers: []BotCheckHeader{{"X Bad", "1"}, {"Café", "2"}, {"X-Nul", "a\x00b"}, {"X-Break", "a\r\nX-Evil: 1"}, {"Accept", "*/*"}}})
	if !reflect.DeepEqual(body["headers"], [][2]string{{"Accept", "*/*"}}) || body["truncated"] != true {
		t.Fatalf("not HTTP: %v", body)
	}
	if raw, _ := json.Marshal(mustBody(t, BotCheckRequest{IP: "203.0.113.7"})); string(raw) != `{"headers":[],"ip":"203.0.113.7"}` {
		t.Fatalf("no headers: %s", raw)
	}

	// As a set, repeats of one name are one header, whatever their case.
	repeats := make([]BotCheckHeader, 150)
	for i := range repeats {
		repeats[i] = BotCheckHeader{"Accept", "a"}
	}
	repeats[1].Name = "accept"
	set, _ := mustBody(t, BotCheckRequest{IP: "203.0.113.7:51234", Headers: repeats, HeaderOrderUnknown: true})["headers"].(map[string]string)
	if len(set) != 1 || set["Accept"] != strings.TrimSuffix(strings.Repeat("a, ", 150), ", ") {
		t.Fatalf("repeats: %v", set)
	}
}

func TestBotCheckSendsTheMethodURLVersionAndTLSAsTheAPIReadsThem(t *testing.T) {
	for in, want := range map[string]string{
		"https://Shop.Example:8443/a/b?c=d#e": "https://Shop.Example:8443/a/b",
		"https://203.0.113.7/login":           "https://203.0.113.7/login",
		"http://shop.example":                 "http://shop.example",
		"/sign-in?x=1":                        "/sign-in",
		"wss://shop.example/socket":           "https://shop.example/socket", // a WebSocket is the same origin over http(s)
		"ws://shop.example/socket":            "http://shop.example/socket",
		// The Host header is the visitor's: one the API could not read goes as the path alone.
		"https://exa mple.com/login": "/login", "https://shop.example.123/login": "/login", "https://1.2.3.256/login": "/login",
		"https://shop.example:99999/login": "/login", "https://[2001:db8::1]/login": "/login", "https://xn--zz.example/login": "/login",
		"https://a:b:c/login": "/login", "https://shop%2eexample/login": "/login",
		// Anything that is not a path or an http(s) URL is left out, and so is one over 4096 characters (never cut).
		"*": "", "ftp://shop.example/x": "", "shop.example/x": "", "?q=1": "",
		"https://shop.example/" + strings.Repeat("p", 4096): "", "/" + strings.Repeat("p", 4095): "/" + strings.Repeat("p", 4095),
	} {
		if got := botCheckURL(in); got != want {
			t.Fatalf("url %.60q: %.60q", in, got)
		}
	}
	for in, want := range map[string]interface{}{"GET": "GET", " post ": "post", "PROPFIND": "PROPFIND", "M-SEARCH": nil, strings.Repeat("M", 17): nil} {
		if got := mustBody(t, BotCheckRequest{IP: "203.0.113.7", Method: in})["method"]; got != want {
			t.Fatalf("method %q: %v", in, got)
		}
	}
	for in, want := range map[string]interface{}{"1.0": "1.0", "HTTP/1.1": "1.1", "HTTP/2.0": "2", "h2": "2", "3": "3", "h3": "3", "HTTP/1.2": nil, "spdy/3": nil} {
		if got := mustBody(t, BotCheckRequest{IP: "203.0.113.7", HTTPVersion: in})["httpVersion"]; got != want {
			t.Fatalf("httpVersion %q: %v", in, got)
		}
	}
	tls := mustBody(t, BotCheckRequest{IP: "203.0.113.7", TLS: &BotCheckTLS{Ciphers: strings.Repeat("c", 5000), JA4: strings.Repeat("j", 129)}})["tls"]
	if !reflect.DeepEqual(tls, map[string]string{"ciphers": strings.Repeat("c", 4096)}) {
		t.Fatalf("tls: %v", tls)
	}
	if b := mustBody(t, BotCheckRequest{IP: "203.0.113.7", TLS: &BotCheckTLS{JA4: strings.Repeat("j", 129)}}); b["tls"] != nil {
		t.Fatalf("a JA4 over 128 characters went: %v", b["tls"])
	}
}

func TestBotCheckCutsAValueWithoutSplittingACharacter(t *testing.T) {
	if got := cutChars(strings.Repeat("a", 5000), 4096); len(got) != 4096 {
		t.Fatalf("ascii: %d", len(got))
	}
	// 4096 characters in 8192 bytes: the API counts characters, so nothing is cut.
	if e := strings.Repeat("é", 4096); cutChars(e, 4096) != e {
		t.Fatal("a value of 4096 two-byte characters was cut")
	}
	// An emoji is two characters to the API: 1 + 2*2048 = 4097, so the last one goes whole.
	got := cutChars("a"+strings.Repeat("😀", 2048), 4096)
	if got != "a"+strings.Repeat("😀", 2047) || !utf8.ValidString(got) {
		t.Fatalf("emoji: %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
}

func TestBotCheckKeepsWhatItDoesNotKnow(t *testing.T) {
	dr, _ := fakeBotCheckAPI(t, 200, nil, `{"bot":{"result":"suspected","category":"ai_browser","provider":null,"name":null,
		"identity":"claimed","verifiedBy":null,"confidence":"low","rule":"browser.future_rule","futureField":true,"reasons":[
		{"code":"new_sign","text":"A sign this version does not know."},null,"junk",{"text":"no code"},{"code":7}]},
		"network":{"asn":"AS15169","asnOrg":"Google LLC","countryCode":"US","hosting":"yes"},
		"suggestion":"throttle","rulesVersion":"2027.01.01-1","evidenceId":"ev_1"}`)
	b, err := dr.BotCheck(context.Background(), BotCheckRequest{IP: "203.0.113.7", Headers: []BotCheckHeader{{"User-Agent", "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if b.Bot.Result != "suspected" || b.Bot.Category != "ai_browser" || b.Bot.Provider != "" || b.Bot.Identity != "claimed" || b.Bot.Rule != "browser.future_rule" {
		t.Fatalf("bot: %+v", b.Bot)
	}
	if !reflect.DeepEqual(b.Bot.Reasons, []BotCheckReason{{Code: "new_sign", Text: "A sign this version does not know."}}) {
		t.Fatalf("reasons: %+v", b.Bot.Reasons)
	}
	if !reflect.DeepEqual(b.Network, &BotCheckNetwork{ASNOrg: "Google LLC", CountryCode: "US"}) {
		t.Fatalf("network: %+v", b.Network)
	}
	if b.Suggestion != "throttle" || b.RulesVersion != "2027.01.01-1" || b.Raw["evidenceId"] != "ev_1" || b.Raw["bot"].(map[string]interface{})["futureField"] != true {
		t.Fatalf("unknown values and fields: %+v", b)
	}

	// What cannot be read is "cannot tell": not_detected and allow, never a block.
	empty := ParseBotCheck(nil)
	if empty.Bot.Reasons == nil || len(empty.Bot.Reasons) != 0 || empty.Bot.Result != "not_detected" || empty.Network != nil || empty.Suggestion != "allow" {
		t.Fatalf("nil: %+v", empty)
	}
	if junk := ParseBotCheck(map[string]interface{}{"bot": "x", "network": "y", "suggestion": 1.0}); junk.Bot.Result != "not_detected" || junk.Network != nil || junk.Suggestion != "allow" {
		t.Fatalf("junk: %+v", junk)
	}
	if n := ParseBotCheck(map[string]interface{}{"network": map[string]interface{}{"asn": -3.0}}).Network; n == nil || n.ASN != 0 {
		t.Fatalf("a negative ASN: %+v", n)
	}
}

func TestBotCheckAPIErrorsComeThroughLikeTheOtherCalls(t *testing.T) {
	req := BotCheckRequest{IP: "203.0.113.7", Headers: []BotCheckHeader{{"User-Agent", "curl/8.7.1"}}}
	for _, tc := range []struct {
		status int
		header http.Header
		answer string
		code   string
		retry  int
	}{
		{400, nil, `{"code":"invalid_ip","error":"ip must be an IPv4 or IPv6 address"}`, "invalid_ip", 0},
		{409, nil, `{"code":"device_risk_off","error":"Device risk is off for this workspace."}`, "device_risk_off", 0},
		{429, http.Header{"Retry-After": {"7"}}, `{"code":"rate_limited","error":"Too many bot checks."}`, "rate_limited", 7},
	} {
		dr, _ := fakeBotCheckAPI(t, tc.status, tc.header, tc.answer)
		_, err := dr.BotCheck(context.Background(), req)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || apiErr.Code != tc.code || apiErr.RetryAfter != tc.retry || errors.Is(err, ErrFeature) {
			t.Fatalf("%d: want an *APIError %s, got %v", tc.status, tc.code, err)
		}
	}
	dr, _ := fakeBotCheckAPI(t, 403, nil, `{"error":"feature_not_in_plan","feature":"device_risk"}`)
	_, err := dr.BotCheck(context.Background(), req)
	if !errors.Is(err, ErrFeatureNotInPlan) || !errors.Is(err, ErrFeature) {
		t.Fatalf("feature refusal: %v", err)
	}
}
