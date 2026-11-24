package devicerisk

// Spawns the shared Node fake Touchque API (sdks/testing/fake-touchque-api.mjs)
// for contract tests: verifies this package's requests are signed exactly like
// the real backend expects, using a real HTTP round trip (not mocks).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type fakeAPI struct {
	baseURL string
	cmd     *exec.Cmd
	t       *testing.T
}

// fakeScript finds testing/fake-touchque-api.mjs next to this module (sdks/
// in the monorepo) or above it.
func fakeScript(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("could not resolve the working directory: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "testing", "fake-touchque-api.mjs")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("testing/fake-touchque-api.mjs not found")
		}
		dir = parent
	}
}

func startFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is required for contract tests")
	}
	cmd := exec.Command("node", fakeScript(t))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("could not attach stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start fake-touchque-api.mjs: %v", err)
	}

	decoder := json.NewDecoder(stdout)
	var line struct {
		Port int `json:"port"`
	}
	done := make(chan error, 1)
	go func() { done <- decoder.Decode(&line) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("could not read fake-touchque-api.mjs port: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fake-touchque-api.mjs to start")
	}

	api := &fakeAPI{baseURL: "http://127.0.0.1:" + strconv.Itoa(line.Port), cmd: cmd, t: t}
	t.Cleanup(api.close)
	return api
}

func (f *fakeAPI) close() {
	if f.cmd.Process != nil {
		_ = f.cmd.Process.Kill()
		_ = f.cmd.Wait()
	}
}

func (f *fakeAPI) call(path string, body map[string]interface{}) {
	f.t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(f.baseURL+path, "application/json", bytes.NewReader(b))
	if err != nil {
		f.t.Fatalf("call %s: %v", path, err)
	}
	_ = resp.Body.Close()
}

func (f *fakeAPI) opts(o map[string]interface{}) { f.call("/__test/opts", o) }

func (f *fakeAPI) getJSON(path string, out interface{}) {
	f.t.Helper()
	resp, err := http.Get(f.baseURL + path)
	if err != nil {
		f.t.Fatalf("%s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, out)
}

// calls are every signed call the fake received.
func (f *fakeAPI) calls() []map[string]interface{} {
	var out []map[string]interface{}
	f.getJSON("/__test/calls", &out)
	return out
}

// lastDeviceRiskSearch is the query of the last GET /device-risk/events.
func (f *fakeAPI) lastDeviceRiskSearch() map[string]interface{} {
	var out map[string]interface{}
	f.getJSON("/__test/last-device-risk-search", &out)
	return out
}

// lastDeviceRiskActivity is the body of the last POST /device-risk/activity.
func (f *fakeAPI) lastDeviceRiskActivity() map[string]interface{} {
	var out map[string]interface{}
	f.getJSON("/__test/last-device-risk-activity", &out)
	return out
}

func (f *fakeAPI) client(t *testing.T) *Client {
	t.Helper()
	return NewClient(&Config{APIKey: "tq_test_key", APISecret: "test_secret", BaseURL: f.baseURL, TimeoutMs: 5000})
}
