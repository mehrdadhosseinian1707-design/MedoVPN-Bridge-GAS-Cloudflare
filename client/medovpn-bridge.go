// MedoVPN is a cross-platform local HTTP/HTTPS proxy for the Apps Script relay.
// Its browser and GUI listeners are restricted to loopback addresses.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxRequestBody = 32 << 20
	maxRelayJSON   = 64 << 20
	// No GAS URL or AUTH_KEY ship with the binary. Set GAS_SCRIPT_URL and
	// GAS_AUTH_KEY (env vars), or configure them in the GUI, before starting
	// the proxy. Shipping real credentials in source let anyone with the
	// binary use your relay and your GAS quota.
	defaultGASURL       = ""
	defaultGASAuthKey   = ""
	defaultBrowserProxy = "127.0.0.1:5555"
	defaultV2RayProxy   = "127.0.0.1:10808"
	defaultGUIAddress   = "127.0.0.1:5560"
	builtInProfileID    = "builtin-default"
)

type relayRequest struct {
	Key     string            `json:"k"`
	URL     string            `json:"u"`
	Method  string            `json:"m"`
	Headers map[string]string `json:"h"`
	Body    string            `json:"b"`
	// Redirect=false asks Code.gs / the Worker NOT to follow 3xx upstream
	// (followRedirects:false / redirect:"manual"). Google sign-in is a chain
	// of 302s that each set cookies; if they are followed upstream the
	// browser never sees the hops and loses the cookies. Always sent.
	Redirect bool `json:"r"`
}

type relayResponse struct {
	Status  int          `json:"s"`
	Headers relayHeaders `json:"h"`
	Body    string       `json:"b"`
	Error   string       `json:"e"`
}

// relayHeaders accepts each header value as a JSON string OR an array of
// strings. Apps Script's getAllHeaders() returns repeated headers (several
// Set-Cookie lines) as an array, which a map[string]string rejects, and the
// whole reply then fails with "returned HTTP 200 instead of relay JSON".
type relayHeaders map[string]json.RawMessage

var setCookieBoundary = regexp.MustCompile(`,\s*[A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]+=`)

// splitSetCookie splits one string that holds several Set-Cookie lines.
// Preferred separator is "\n" (make Code.gs join with it). As a fallback a
// ", name=" boundary is used; the comma inside "Expires=Wed, 21 Oct ..." is
// not followed by name=, so it is left alone.
func splitSetCookie(value string) []string {
	var parts []string
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		start := 0
		for _, loc := range setCookieBoundary.FindAllStringIndex(line, -1) {
			parts = append(parts, strings.TrimSpace(line[start:loc[0]]))
			start = loc[0] + 1
		}
		parts = append(parts, strings.TrimSpace(line[start:]))
	}
	return parts
}

// values returns every value of one header as separate strings.
func (h relayHeaders) values(name string, raw json.RawMessage) []string {
	var list []string
	isArray := true
	if err := json.Unmarshal(raw, &list); err != nil {
		isArray = false
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil
		}
		list = []string{single}
	}
	isCookie := strings.EqualFold(name, "set-cookie")
	var out []string
	for _, item := range list {
		if isCookie {
			if isArray && len(list) >= 2 {
				// A real array already separates the cookies, so a comma
				// inside one value (a=1,b=2) must not be split again.
				for _, line := range strings.Split(item, "\n") {
					if line = strings.TrimSpace(line); line != "" {
						out = append(out, line)
					}
				}
			} else {
				out = append(out, splitSetCookie(item)...)
			}
		} else if strings.Contains(item, "\n") {
			for _, line := range strings.Split(item, "\n") {
				if line = strings.TrimSpace(line); line != "" {
					out = append(out, line)
				}
			}
		} else {
			out = append(out, item)
		}
	}
	return out
}

func (h relayHeaders) count(name string) int {
	n := 0
	for k, raw := range h {
		if strings.EqualFold(k, name) {
			n += len(h.values(k, raw))
		}
	}
	return n
}

// hopByHop headers must never be copied between the two sides of a proxy.
var hopByHop = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true,
	"proxy-authorization": true, "proxy-connection": true, "te": true,
	"trailer": true, "transfer-encoding": true, "upgrade": true, "expect": true,
}

// connectionTokens returns the lower-cased header names listed in every
// Connection header ("Connection: keep-alive, X-Foo" -> keep-alive, x-foo).
func connectionTokens(h http.Header) map[string]bool {
	tokens := make(map[string]bool)
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.ToLower(strings.TrimSpace(token)); token != "" {
				tokens[token] = true
			}
		}
	}
	return tokens
}

// stripHopByHop removes the headers that must not cross a proxy: the fixed
// hop-by-hop list and every header the Connection header names.
func stripHopByHop(h http.Header) {
	tokens := connectionTokens(h) // must be read before Connection is deleted
	h.Del("Connection")
	for name := range hopByHop {
		h.Del(name)
	}
	for token := range tokens {
		h.Del(token)
	}
}

// relayStatusError lets relay() ask the caller for a specific HTTP status
// (413/501) instead of the generic 502.
type relayStatusError struct {
	status int
	msg    string
}

func (e *relayStatusError) Error() string { return e.msg }

// responseMemoryBudget bounds the memory held by relay responses that are
// still being delivered to browsers.
const responseMemoryBudget = 256 << 20

// byteBudget is a simple memory budget. The first holder always proceeds when
// nothing is held, so one very large download can never block forever.
type byteBudget struct {
	mu    sync.Mutex
	used  int64
	limit int64
	wake  chan struct{}
}

func newByteBudget(limit int64) *byteBudget {
	return &byteBudget{limit: limit, wake: make(chan struct{})}
}

func (b *byteBudget) acquire(ctx context.Context, n int64) error {
	if b == nil {
		return nil
	}
	for {
		b.mu.Lock()
		if b.used == 0 || b.used+n <= b.limit {
			b.used += n
			b.mu.Unlock()
			return nil
		}
		wake := b.wake
		b.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (b *byteBudget) release(n int64) {
	if b == nil || n <= 0 {
		return
	}
	b.mu.Lock()
	b.used -= n
	close(b.wake)
	b.wake = make(chan struct{})
	b.mu.Unlock()
}

// force adds bytes that are already in memory without waiting.
func (b *byteBudget) force(n int64) {
	if b == nil || n <= 0 {
		return
	}
	b.mu.Lock()
	b.used += n
	b.mu.Unlock()
}

// budgetBody gives its budget back once, when the body is closed.
type budgetBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *budgetBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

const (
	maxGASURLBytes    = 2000 // Apps Script UrlFetch URL limit is about 2 KB
	maxGASHeaderBytes = 8000 // and about 8 KB per header block
	maxParallelRelays = 12
)

type proxyApp struct {
	scriptURL         string
	key               string
	caCert            *x509.Certificate
	caKey             crypto.PrivateKey
	http              *http.Client
	dashboardPort     int
	dashboardHandler  http.Handler
	browserProbeToken string
	lastBrowserSeen   atomic.Int64
	sentRequests      atomic.Uint64
	sentBytes         atomic.Uint64
	receivedResponses atomic.Uint64
	receivedBytes     atomic.Uint64
	certCache         sync.Map // host -> hostCertEntry
	activeMu          sync.Mutex
	activeClosed      bool
	activeConns       map[net.Conn]struct{}
	metrics           *relayMetrics
	onGASResult       func(bool, string)
	baseCtx           context.Context
	cancelAll         context.CancelFunc
	relaySlots        chan struct{}
	certCount         atomic.Int64
	memBudget         *byteBudget
	retries           atomic.Uint64
	queueWaitMS       atomic.Uint64 // total milliseconds spent waiting for a relay slot
	certRejects       atomic.Uint64
	rejectMu          sync.Mutex
	rejectLogged      map[string]time.Time
}

type relayMetrics struct {
	mu                  sync.RWMutex
	known               bool
	connected           bool
	quality             string
	latencyMS           float64
	fullLatencyMS       float64
	jitterMS            float64
	jitterReady         bool
	successRate         float64
	sampleCount         int
	failureCount        int
	consecutiveFailures int
	samples             []float64
	outcomes            []bool
	lastSuccessAt       time.Time
	errorMessage        string
	updatedAt           time.Time
}

type relayMetricsSnapshot struct {
	Known         bool    `json:"metricKnown"`
	Quality       string  `json:"connectionQuality"`
	Connected     bool    `json:"metricConnected"`
	LatencyMS     float64 `json:"latencyMs"`
	FullLatencyMS float64 `json:"fullLatencyMs"`
	LatencyReady  bool    `json:"latencyReady"`
	JitterMS      float64 `json:"jitterMs"`
	JitterReady   bool    `json:"jitterReady"`
	SuccessRate   float64 `json:"metricSuccessRate"`
	SampleCount   int     `json:"metricSampleCount"`
	FailureCount  int     `json:"metricFailureCount"`
	ErrorMessage  string  `json:"metricError"`
	UpdatedAt     string  `json:"metricUpdatedAt"`
}

func (m *relayMetrics) reset() {
	m.mu.Lock()
	m.known = false
	m.connected = false
	m.quality = "IDLE"
	m.latencyMS = 0
	m.fullLatencyMS = 0
	m.jitterMS = 0
	m.jitterReady = false
	m.successRate = 0
	m.sampleCount = 0
	m.failureCount = 0
	m.consecutiveFailures = 0
	m.samples = nil
	m.outcomes = nil
	m.lastSuccessAt = time.Time{}
	m.errorMessage = "Waiting for the first successful GAS response."
	m.updatedAt = time.Time{}
	m.mu.Unlock()
}

// recordSuccess records one browser request that succeeded. firstByte is the
// time until Apps Script's response headers arrived (quality and jitter are
// computed from it); full is the time until the body was read and decoded.
func (m *relayMetrics) recordSuccess(firstByte, full time.Duration) {
	if m == nil {
		return
	}
	latency := float64(firstByte) / float64(time.Millisecond)
	if latency < 0 {
		latency = 0
	}
	fullLatency := float64(full) / float64(time.Millisecond)
	if fullLatency < 0 {
		fullLatency = 0
	}
	m.mu.Lock()
	m.known = true
	m.connected = true
	m.latencyMS = latency
	m.fullLatencyMS = fullLatency
	m.lastSuccessAt = time.Now()
	m.consecutiveFailures = 0
	m.errorMessage = ""
	m.updatedAt = time.Now()
	m.recordOutcomeLocked(true)
	m.samples = append(m.samples, latency)
	if len(m.samples) > 12 {
		m.samples = append([]float64(nil), m.samples[len(m.samples)-12:]...)
	}
	m.jitterReady = len(m.samples) > 1
	m.jitterMS = 0
	if m.jitterReady {
		for i := 1; i < len(m.samples); i++ {
			delta := m.samples[i] - m.samples[i-1]
			if delta < 0 {
				delta = -delta
			}
			m.jitterMS += delta
		}
		m.jitterMS /= float64(len(m.samples) - 1)
	}
	m.recalculateQualityLocked()
	m.mu.Unlock()
}

func (m *relayMetrics) recordFailure(message string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.known = true
	m.consecutiveFailures++
	m.errorMessage = strings.TrimSpace(message)
	m.updatedAt = time.Now()
	m.recordOutcomeLocked(false)
	m.recalculateQualityLocked()
	m.mu.Unlock()
}

func (m *relayMetrics) recordOutcomeLocked(success bool) {
	m.outcomes = append(m.outcomes, success)
	if len(m.outcomes) > 20 {
		m.outcomes = append([]bool(nil), m.outcomes[len(m.outcomes)-20:]...)
	}
	m.sampleCount = len(m.outcomes)
	successes := 0
	for _, outcome := range m.outcomes {
		if outcome {
			successes++
		}
	}
	m.failureCount = m.sampleCount - successes
	if m.sampleCount > 0 {
		m.successRate = 100 * float64(successes) / float64(m.sampleCount)
	} else {
		m.successRate = 0
	}
}

func (m *relayMetrics) recalculateQualityLocked() {
	m.connected = !m.lastSuccessAt.IsZero() && time.Since(m.lastSuccessAt) <= 90*time.Second
	if len(m.outcomes) == 0 {
		m.quality = "IDLE"
		return
	}
	lastSucceeded := m.outcomes[len(m.outcomes)-1]
	switch {
	case !m.connected || m.consecutiveFailures >= 3 || (m.sampleCount >= 5 && m.successRate < 50):
		m.quality = "BAD"
	case lastSucceeded && m.successRate >= 80 && m.latencyMS <= 10000 && (!m.jitterReady || m.jitterMS <= 3500):
		m.quality = "GOOD"
	default:
		m.quality = "NORMAL"
	}
}

func (m *relayMetrics) snapshot() relayMetricsSnapshot {
	if m == nil {
		return relayMetricsSnapshot{Quality: "DISCONNECTED", ErrorMessage: "No GAS connection measurement yet."}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	connected := !m.lastSuccessAt.IsZero() && time.Since(m.lastSuccessAt) <= 90*time.Second
	snapshot := relayMetricsSnapshot{
		Known:   m.known,
		Quality: m.quality, Connected: connected,
		LatencyMS: m.latencyMS, FullLatencyMS: m.fullLatencyMS, LatencyReady: len(m.samples) > 0,
		JitterMS: m.jitterMS, JitterReady: m.jitterReady,
		SuccessRate: m.successRate, SampleCount: m.sampleCount, FailureCount: m.failureCount,
		ErrorMessage: m.errorMessage,
	}
	if m.updatedAt.IsZero() {
		snapshot.Quality = "IDLE"
	} else if time.Since(m.updatedAt) > 2*time.Minute || (!connected && len(m.outcomes) > 0 && m.outcomes[len(m.outcomes)-1]) {
		snapshot.Quality = "IDLE"
		snapshot.Connected = false
	} else {
		snapshot.UpdatedAt = m.updatedAt.Format(time.RFC3339)
	}
	return snapshot
}

// defaultStateDir returns a per-user directory to store the CA and settings
// in, so the CA Firefox trusts doesn't silently change (and a fresh one
// doesn't get generated) just because the proxy was launched from a
// different working directory. Falls back to "." if the OS config dir is
// unavailable.
func defaultStateDir() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return "."
	}
	return filepath.Join(dir, "medovpn")
}

func main() {
	stateDir := defaultStateDir()
	listen := flag.String("listen", defaultBrowserProxy, "default local browser proxy address (must be loopback)")
	upstreamProxy := flag.String("upstream-proxy", "http://"+defaultV2RayProxy, "default V2RayNG local proxy URL: http://IP:PORT or socks5://IP:PORT")
	guiListen := flag.String("gui-listen", defaultGUIAddress, "local GUI web address (must be loopback)")
	openGUI := flag.Bool("open-gui", true, "open the local control panel in the system browser")
	settingsFile := flag.String("settings-file", filepath.Join(stateDir, "gas-proxy-settings.json"), "file for GUI settings and saved GAS profiles (contains secrets; keep this private)")
	caDir := flag.String("ca-dir", filepath.Join(stateDir, "gas-proxy-ca"), "directory for the local HTTPS interception CA")
	caCertPath := flag.String("ca-cert", "", "CA certificate file (defaults to mycert.crt, then ca.crt in -ca-dir)")
	caKeyPath := flag.String("ca-key", "", "matching CA private key file (defaults to the selected certificate's .key sibling)")
	flag.Parse()

	scriptURL := strings.TrimSpace(os.Getenv("GAS_SCRIPT_URL"))
	if scriptURL == "" {
		scriptURL = defaultGASURL
	}
	key := strings.TrimSpace(os.Getenv("GAS_AUTH_KEY"))
	if key == "" {
		key = defaultGASAuthKey
	}
	if scriptURL == "" || key == "" {
		log.Printf("no GAS_SCRIPT_URL/GAS_AUTH_KEY set (and no built-in default); configure them in the GUI before starting the proxy")
	}
	logs := &logBuffer{maxLines: 500}
	log.SetFlags(log.Ldate | log.Ltime)
	// io.MultiWriter aborts on the first writer's error, so if stderr is
	// invalid (common for a GUI-subsystem Windows build with no console)
	// the in-memory log buffer the GUI reads from would never receive any
	// lines. Write to both independently instead.
	log.SetOutput(tolerantMultiWriter{os.Stderr, logs})
	// The log buffer now exists, so warnings from loading the saved settings
	// reach the GUI log too.
	initial, profiles, activeProfileID, loadErr := loadSavedState(*settingsFile, settingsFromDefaults(*listen, *upstreamProxy, scriptURL, key))

	guiHost, _, splitErr := net.SplitHostPort(*guiListen)
	if splitErr != nil || !isLoopback(guiHost) {
		log.Fatal("GUI must bind to a loopback address such as 127.0.0.1:5560")
	}
	guiListener, err := net.Listen("tcp", *guiListen)
	if err != nil {
		log.Fatalf("start local GUI at %s: %v", *guiListen, err)
	}
	controller := &proxyController{
		caDir: *caDir, caCertPath: *caCertPath, caKeyPath: *caKeyPath,
		metrics: &relayMetrics{}, state: "stopped",
	}
	if uploadedCert, _, uploadedErr := savedUploadedCAPaths(*caDir); uploadedErr == nil && uploadedCert != "" {
		controller.caUploaded = true
	}
	guiAddr := guiListener.Addr().String()
	probeToken, err := randomToken()
	if err != nil {
		_ = guiListener.Close()
		log.Fatalf("create browser probe token: %v", err)
	}
	ui := &clientUI{
		defaults:        initial,
		defaultGASURL:   scriptURL,
		defaultAuthKey:  key,
		profiles:        profiles,
		activeProfileID: activeProfileID,
		controller:      controller,
		logs:            logs,
		guiAddress:      guiAddr,
		probeToken:      probeToken,
		settingsFile:    *settingsFile,
		quit:            make(chan struct{}, 1),
		settingsLocked:  loadErr,
	}
	guiServer := &http.Server{Addr: guiAddr, Handler: ui, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := guiServer.Serve(guiListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("GUI server stopped: %v", err)
		}
	}()
	guiURL := "http://" + guiAddr + "/"
	log.Printf("GUI ready at %s", guiURL)
	log.Printf("Default browser proxy: %s; V2RayNG upstream: %s", initial.browserAddress(), initial.v2rayAddress())
	if *openGUI {
		openSystemBrowser(guiURL)
	} else {
		log.Printf("Open the control panel manually at %s", guiURL)
	}

	// os.Interrupt alone misses SIGTERM, which is how `kill` and most
	// service managers (systemd, Docker, etc.) ask a process to stop; without
	// it those paths skip the graceful shutdown entirely.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case <-ui.quit:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	controller.stop(shutdownCtx)
	_ = guiServer.Shutdown(shutdownCtx)
	log.Printf("GUI and proxy stopped")
}

type relaySettings struct {
	BrowserIP   string `json:"browserIP"`
	BrowserPort int    `json:"browserPort"`
	V2RayIP     string `json:"v2rayIP"`
	V2RayPort   int    `json:"v2rayPort"`
	V2RayType   string `json:"v2rayType"`
	GASURL      string `json:"gasURL"`
	AuthKey     string `json:"authKey"`
}

type gasProfile struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	GASURL  string `json:"gasURL"`
	AuthKey string `json:"authKey"`
}

type savedGUIState struct {
	Version         int           `json:"version"`
	Settings        relaySettings `json:"settings"`
	Profiles        []gasProfile  `json:"profiles"`
	ActiveProfileID string        `json:"activeProfileID"`
}

func (s relaySettings) browserAddress() string {
	return net.JoinHostPort(strings.TrimSpace(s.BrowserIP), strconv.Itoa(s.BrowserPort))
}

func (s relaySettings) v2rayAddress() string {
	return net.JoinHostPort(strings.TrimSpace(s.V2RayIP), strconv.Itoa(s.V2RayPort))
}

func settingsFromDefaults(listenAddress, upstreamURL, scriptURL, key string) relaySettings {
	browserIP, browserPort := splitAddressDefaults(listenAddress, "127.0.0.1", 5555)
	v2rayIP, v2rayPort, v2rayType := "127.0.0.1", 10808, "http"
	if u, err := url.Parse(strings.TrimSpace(upstreamURL)); err == nil && u.Hostname() != "" {
		v2rayIP = u.Hostname()
		if u.Scheme == "socks5" || u.Scheme == "socks5h" {
			v2rayType, v2rayPort = "socks5", 1080
		} else if u.Scheme == "https" {
			v2rayType, v2rayPort = "http", 443
		} else {
			v2rayType, v2rayPort = "http", 80
		}
		if port := u.Port(); port != "" {
			if n, err := strconv.Atoi(port); err == nil {
				v2rayPort = n
			}
		}
	}
	return relaySettings{
		BrowserIP: browserIP, BrowserPort: browserPort,
		V2RayIP: v2rayIP, V2RayPort: v2rayPort, V2RayType: v2rayType,
		GASURL: scriptURL, AuthKey: key,
	}
}

// backupCorruptSettings keeps a copy of an unparsable settings file so the
// next save cannot silently destroy the user's saved profiles.
func backupCorruptSettings(path string, data []byte, cause error) {
	backup := path + ".corrupt-" + time.Now().Format("20060102-150405")
	if err := os.WriteFile(backup, data, 0600); err != nil {
		log.Printf("saved GUI settings ignored (%v); could not keep a copy at %s: %v", cause, backup, err)
		return
	}
	log.Printf("saved GUI settings ignored (%v); the unreadable file was kept at %s", cause, backup)
}

// loadSavedState returns loadErr != nil when the settings file exists but
// could not be read. The caller must then refuse to overwrite it.
func loadSavedState(path string, defaults relaySettings) (relaySettings, []gasProfile, string, error) {
	defaultGASURL := defaults.GASURL
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaults, nil, builtInProfileID, nil
		}
		log.Printf("saved GUI settings could not be read (%v); they will not be overwritten this session", err)
		return defaults, nil, builtInProfileID, err
	}
	var state savedGUIState
	if err := json.Unmarshal(data, &state); err != nil {
		backupCorruptSettings(path, data, err)
		return defaults, nil, builtInProfileID, nil
	}
	if state.Settings == (relaySettings{}) && len(state.Profiles) == 0 {
		// Read settings written by earlier versions, which stored fields at the
		// top level and did not have a saved-profile list.
		var legacy relaySettings
		if err := json.Unmarshal(data, &legacy); err != nil {
			backupCorruptSettings(path, data, err)
			return defaults, nil, builtInProfileID, nil
		}
		state.Settings = legacy
	}
	saved := state.Settings
	if saved.BrowserIP != "" {
		defaults.BrowserIP = saved.BrowserIP
	}
	if saved.BrowserPort > 0 {
		defaults.BrowserPort = saved.BrowserPort
	}
	if saved.V2RayIP != "" {
		defaults.V2RayIP = saved.V2RayIP
	}
	if saved.V2RayPort > 0 {
		defaults.V2RayPort = saved.V2RayPort
	}
	if saved.V2RayType != "" {
		defaults.V2RayType = saved.V2RayType
	}
	if state.Version < 2 && saved.V2RayIP == "127.0.0.1" && saved.V2RayPort == 8080 && (saved.V2RayType == "" || saved.V2RayType == "http") {
		defaults.V2RayPort = 10808
	}
	if saved.GASURL != "" {
		defaults.GASURL = saved.GASURL
	}
	profiles := normalizeProfiles(state.Profiles)
	activeProfileID := state.ActiveProfileID
	if state.ActiveProfileID == "" && len(profiles) == 0 && saved.GASURL != "" && saved.GASURL != defaultGASURL {
		// defaults.AuthKey at this point is the built-in/env key, not a key
		// that was ever saved for this custom URL (legacy files never stored
		// AuthKey). Pairing them would send the built-in key to an unknown
		// GAS deployment, so leave AuthKey blank and let the user re-enter
		// it for this migrated profile.
		profiles = append(profiles, gasProfile{
			ID: "legacy-saved", Name: "Previously saved GAS",
			GASURL: defaults.GASURL, AuthKey: "",
		})
		activeProfileID = "legacy-saved"
	}
	if activeProfileID == "" {
		for _, profile := range profiles {
			if profile.GASURL == defaults.GASURL {
				activeProfileID = profile.ID
				break
			}
		}
	}
	if activeProfileID != builtInProfileID {
		if profile, ok := findProfile(profiles, activeProfileID); ok {
			defaults.GASURL, defaults.AuthKey = profile.GASURL, profile.AuthKey
		} else {
			activeProfileID = builtInProfileID
			defaults.GASURL = defaultGASURL
		}
	} else {
		defaults.GASURL = defaultGASURL
	}
	return defaults, profiles, activeProfileID, nil
}

func normalizeProfiles(profiles []gasProfile) []gasProfile {
	clean := make([]gasProfile, 0, len(profiles))
	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		profile.ID = strings.TrimSpace(profile.ID)
		profile.Name = strings.TrimSpace(profile.Name)
		profile.GASURL = strings.TrimSpace(profile.GASURL)
		profile.AuthKey = strings.TrimSpace(profile.AuthKey)
		if profile.ID == "" || profile.ID == builtInProfileID || profile.GASURL == "" {
			continue
		}
		if _, exists := seen[profile.ID]; exists {
			continue
		}
		if profile.Name == "" {
			profile.Name = fmt.Sprintf("GAS profile %d", len(clean)+1)
		}
		seen[profile.ID] = struct{}{}
		clean = append(clean, profile)
	}
	return clean
}

func findProfile(profiles []gasProfile, id string) (gasProfile, bool) {
	for _, profile := range profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return gasProfile{}, false
}

func splitAddressDefaults(address, defaultHost string, defaultPort int) (string, int) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return defaultHost, defaultPort
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		port = defaultPort
	}
	if host == "" {
		host = defaultHost
	}
	return host, port
}

// tolerantMultiWriter writes to every writer and keeps going even if one
// fails, unlike io.MultiWriter which stops at the first error.
type tolerantMultiWriter []io.Writer

func (t tolerantMultiWriter) Write(p []byte) (int, error) {
	for _, w := range t {
		_, _ = w.Write(p)
	}
	return len(p), nil
}

type logBuffer struct {
	mu       sync.Mutex
	lines    []string
	maxLines int
}

func (b *logBuffer) Write(p []byte) (int, error) {
	count := len(p)
	for _, line := range strings.Split(strings.TrimRight(string(p), "\r\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		b.mu.Lock()
		b.lines = append(b.lines, line)
		if b.maxLines > 0 && len(b.lines) > b.maxLines {
			b.lines = append([]string(nil), b.lines[len(b.lines)-b.maxLines:]...)
		}
		b.mu.Unlock()
	}
	return count, nil
}

func (b *logBuffer) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.lines...)
}

// startError tells the GUI which component failed to start, so it does not
// have to guess from the error text.
type startError struct {
	component string // "settings", "v2ray", "gas", "ca" or "listen"
	err       error
}

func (e *startError) Error() string { return e.err.Error() }
func (e *startError) Unwrap() error { return e.err }

type proxyController struct {
	mu             sync.Mutex
	state          string // "stopped", "starting", "running" or "stopping"
	gen            uint64
	startCancel    context.CancelFunc
	startDone      chan struct{}
	stopDone       chan struct{}
	server         *http.Server
	listener       net.Listener
	app            *proxyApp
	caDir          string
	caCertPath     string
	caKeyPath      string
	uploadedCAPath string
	caCertificate  []byte
	caUploaded     bool
	caFingerprint  string
	caPath         string
	caWarning      string
	caExpires      time.Time
	v2rayKnown     bool
	v2rayConnected bool
	v2rayMessage   string
	gasKnown       bool
	gasConnected   bool
	gasMessage     string
	metrics        *relayMetrics
	testKnown      bool
	test           gasTestResult
	testAt         time.Time
	runHash        string
}

type controllerSnapshot struct {
	State              string  `json:"state"`
	Running            bool    `json:"running"`
	BrowserAddress     string  `json:"browserAddress"`
	BrowserConnected   bool    `json:"browserConnected"`
	BrowserLastSeen    int64   `json:"browserLastSeen"`
	V2RayKnown         bool    `json:"v2rayKnown"`
	V2RayConnected     bool    `json:"v2rayConnected"`
	V2RayMessage       string  `json:"v2rayMessage"`
	GASKnown           bool    `json:"gasKnown"`
	GASConnected       bool    `json:"gasConnected"`
	GASMessage         string  `json:"gasMessage"`
	SentRequests       uint64  `json:"sentRequests"`
	SentBytes          uint64  `json:"sentBytes"`
	ReceivedResponses  uint64  `json:"receivedResponses"`
	ReceivedBytes      uint64  `json:"receivedBytes"`
	MetricKnown        bool    `json:"metricKnown"`
	MetricConnected    bool    `json:"metricConnected"`
	ConnectionQuality  string  `json:"connectionQuality"`
	LatencyMS          float64 `json:"latencyMs"`
	FullLatencyMS      float64 `json:"fullLatencyMs"`
	LatencyReady       bool    `json:"latencyReady"`
	JitterMS           float64 `json:"jitterMs"`
	JitterReady        bool    `json:"jitterReady"`
	MetricSuccessRate  float64 `json:"metricSuccessRate"`
	MetricSampleCount  int     `json:"metricSampleCount"`
	MetricFailureCount int     `json:"metricFailureCount"`
	MetricError        string  `json:"metricError"`
	MetricUpdatedAt    string  `json:"metricUpdatedAt"`
	GASRetries         uint64  `json:"gasRetries"`
	QueueMS            uint64  `json:"queueMs"`
	CertRejects        uint64  `json:"certRejects"`
	TestKnown          bool    `json:"testKnown"`
	TestOK             bool    `json:"testOk"`
	TestMessage        string  `json:"testMessage"`
	TestV2RayChecked   bool    `json:"testV2RayChecked"`
	TestV2RayConnected bool    `json:"testV2RayConnected"`
	CAUploaded         bool    `json:"caUploaded"`
	CAFingerprint      string  `json:"caFingerprint"`
	CAPath             string  `json:"caPath"`
	CAWarning          string  `json:"caWarning"`
	CAExpires          string  `json:"caExpires"`
}

func (c *proxyController) start(settings relaySettings, guiAddress, probeToken string, dashboardHandler http.Handler) (string, string, error) {
	if err := settings.validateV2Ray(); err != nil {
		return "", "", &startError{"v2ray", err}
	}
	if err := settings.validateNetwork(); err != nil {
		return "", "", &startError{"settings", err}
	}
	if err := settings.validateGASURL(); err != nil {
		return "", "", &startError{"gas", err}
	}
	if strings.TrimSpace(settings.AuthKey) == "" {
		return "", "", &startError{"gas", errors.New("GAS AUTH_KEY is required")}
	}
	// Only flip the state under the lock. Generating the CA (RSA-3072) and
	// probing V2RayNG can take seconds; doing that while holding c.mu froze
	// the status poll and Stop in the GUI. Stop can now cancel a start that
	// is in progress through startCtx.
	c.mu.Lock()
	if c.state != "" && c.state != "stopped" {
		state := c.state
		c.mu.Unlock()
		return "", "", fmt.Errorf("proxy is already %s", state)
	}
	c.state = "starting"
	c.gen++
	myGen := c.gen
	startCtx, cancel := context.WithCancel(context.Background())
	startDone := make(chan struct{})
	c.startCancel, c.startDone = cancel, startDone
	caDir, caCertPath, caKeyPath := c.caDir, c.caCertPath, c.caKeyPath
	c.mu.Unlock()
	published := false
	defer func() {
		cancel()
		if !published {
			c.mu.Lock()
			// If Stop took over (it bumps gen), it owns the state now.
			if c.gen == myGen && c.state == "starting" {
				c.state = "stopped"
			}
			c.mu.Unlock()
		}
		close(startDone)
	}()
	errCancelled := errors.New("start cancelled")

	type caResult struct {
		cert     *x509.Certificate
		key      crypto.PrivateKey
		certPath string
		err      error
	}
	caCh := make(chan caResult, 1)
	go func() {
		cert, key, certPath, _, err := loadOrCreateCA(caDir, caCertPath, caKeyPath)
		caCh <- caResult{cert, key, certPath, err}
	}()
	var ca caResult
	select {
	case ca = <-caCh:
	case <-startCtx.Done():
		// Discarding the result is safe: CA files are written atomically,
		// key first and certificate last.
		return "", "", errCancelled
	}
	if ca.err != nil {
		return "", "", &startError{"ca", fmt.Errorf("load HTTPS interception CA: %w", ca.err)}
	}
	cert, privateKey, certPath := ca.cert, ca.key, ca.certPath
	if startCtx.Err() != nil {
		return "", "", errCancelled
	}
	// timeout 0: no whole-request deadline (it cut large downloads); the
	// transport has a response-header timeout and relay() has its own context.
	client, err := newRelayHTTPClient(settings, 0)
	if err != nil {
		return "", "", &startError{"settings", err}
	}
	if startCtx.Err() != nil {
		return "", "", errCancelled
	}
	probeErr := probeV2RayPort(settings)
	if startCtx.Err() != nil {
		return "", "", errCancelled
	}
	listener, err := net.Listen("tcp", settings.browserAddress())
	if err != nil {
		return "", "", &startError{"listen", fmt.Errorf("start browser proxy at %s: %w", settings.browserAddress(), err)}
	}
	if startCtx.Err() != nil {
		_ = listener.Close()
		return "", "", errCancelled
	}
	_, guiPortText, err := net.SplitHostPort(guiAddress)
	if err != nil {
		_ = listener.Close()
		return "", "", fmt.Errorf("read GUI address: %w", err)
	}
	guiPort, err := strconv.Atoi(guiPortText)
	if err != nil {
		_ = listener.Close()
		return "", "", fmt.Errorf("read GUI port: %w", err)
	}
	baseCtx, cancelAll := context.WithCancel(context.Background())
	app := &proxyApp{
		scriptURL:         settings.GASURL,
		key:               settings.AuthKey,
		caCert:            cert,
		caKey:             privateKey,
		http:              client,
		dashboardPort:     guiPort,
		dashboardHandler:  dashboardHandler,
		browserProbeToken: probeToken,
		baseCtx:           baseCtx,
		cancelAll:         cancelAll,
		relaySlots:        make(chan struct{}, maxParallelRelays),
		memBudget:         newByteBudget(responseMemoryBudget),
	}
	server := &http.Server{
		Addr: listener.Addr().String(), Handler: app,
		ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 90 * time.Second,
	}

	fingerprint := sha256.Sum256(cert.Raw)
	caWarning := ""
	if _, statErr := os.Stat(filepath.Join(caDir, "uploaded-ca.json")); statErr == nil && caCertPath == "" && !strings.Contains(certPath, "uploaded-ca-") {
		caWarning = "An uploaded CA was selected earlier but is not being used; the default CA is active. Upload the CA pair again."
	}

	c.mu.Lock()
	if c.gen != myGen || startCtx.Err() != nil {
		c.mu.Unlock()
		_ = listener.Close()
		cancelAll()
		return "", "", errCancelled
	}
	c.state = "running"
	published = true
	c.v2rayKnown = true
	c.v2rayConnected = probeErr == nil
	if probeErr == nil {
		c.v2rayMessage = "V2RayNG local port is reachable; Test GAS checks the full route."
	} else {
		c.v2rayMessage = "V2RayNG is not reachable: " + probeErr.Error()
	}
	if c.metrics == nil {
		c.metrics = &relayMetrics{}
	}
	c.metrics.reset()
	app.metrics = c.metrics
	app.onGASResult = func(connected bool, message string) {
		c.recordGASFrom(app, connected, message)
	}
	c.server, c.listener, c.app = server, listener, app
	c.runHash = settingsHash(settings)
	c.caCertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	c.caFingerprint = hex.EncodeToString(fingerprint[:])
	c.caPath = certPath
	c.caWarning = caWarning
	c.caExpires = cert.NotAfter
	c.gasKnown = false
	c.gasConnected = false
	c.gasMessage = "Run Test GAS to check the Apps Script route."
	address := listener.Addr().String()
	c.mu.Unlock()
	go func() {
		serveErr := server.Serve(listener)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			message := fmt.Sprintf("browser proxy stopped unexpectedly: %v", serveErr)
			log.Print(message)
			app.shutdownNow()
			c.mu.Lock()
			if c.server == server {
				c.server, c.listener, c.app = nil, nil, nil
				c.state = "stopped"
				c.runHash = ""
				c.gasKnown, c.gasConnected, c.gasMessage = true, false, message
				c.metrics.recordFailure(message)
			}
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		// While Stop is running (state "stopping") it finishes the cleanup
		// itself; only an unrequested end of Serve is handled here.
		if c.server == server && c.state == "running" {
			c.server, c.listener, c.app = nil, nil, nil
			c.state = "stopped"
			c.runHash = ""
		}
		c.mu.Unlock()
	}()
	log.Printf("browser proxy listening at http://%s", address)
	log.Printf("Apps Script relay route: %s via V2RayNG %s (%s)", settings.GASURL, settings.v2rayAddress(), settings.V2RayType)
	log.Printf("HTTPS interception CA: %s; import it into Firefox to inspect HTTPS sites", certPath)
	if until := time.Until(cert.NotAfter); until < 30*24*time.Hour {
		if until < 0 {
			log.Printf("WARNING: the HTTPS interception CA expired on %s; browsers will reject it", cert.NotAfter.Format(time.RFC3339))
		} else {
			log.Printf("WARNING: the HTTPS interception CA expires on %s (in %d days)", cert.NotAfter.Format(time.RFC3339), int(until/(24*time.Hour)))
		}
	}
	if caWarning != "" {
		log.Printf("WARNING: %s", caWarning)
	}
	if probeErr != nil {
		log.Printf("V2RayNG connection check failed: %v", probeErr)
	} else {
		log.Printf("V2RayNG local port reachable at %s", settings.v2rayAddress())
	}
	return address, certPath, nil
}

// shutdownNow aborts everything a proxyApp has in flight.
func (a *proxyApp) shutdownNow() {
	if a.cancelAll != nil {
		a.cancelAll() // abort in-flight relays so they stop burning GAS quota
	}
	a.closeActiveConnections()
	if a.http != nil {
		a.http.CloseIdleConnections()
	}
}

// settingsHash fingerprints the settings a running proxy was started with.
func settingsHash(s relaySettings) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(s.GASURL), strings.TrimSpace(s.AuthKey),
		s.browserAddress(), s.v2rayAddress(), s.V2RayType,
	}, "\x00")))
	return hex.EncodeToString(sum[:])[:16]
}

func (c *proxyController) configMatch(s relaySettings) (running, match bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == "running", c.runHash != "" && c.runHash == settingsHash(s)
}

func (c *proxyController) recordTest(res gasTestResult) {
	c.mu.Lock()
	c.testKnown, c.test, c.testAt = true, res, time.Now()
	c.mu.Unlock()
}

func (c *proxyController) stop(ctx context.Context) {
	c.mu.Lock()
	state := c.state
	if state == "stopping" {
		done := c.stopDone
		c.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
		}
		return
	}
	var startDone chan struct{}
	if state == "starting" {
		if c.startCancel != nil {
			c.startCancel()
		}
		startDone = c.startDone
	}
	server, app := c.server, c.app
	// Bumping gen makes an in-progress start abort at its publish step, and
	// clearing c.app makes recordGASFrom drop late relay callbacks.
	c.gen++
	c.app = nil
	var stopDone chan struct{}
	if state != "" && state != "stopped" {
		c.state = "stopping"
		stopDone = make(chan struct{})
		c.stopDone = stopDone
	}
	metrics := c.metrics
	c.mu.Unlock()
	if startDone != nil {
		select {
		case <-startDone:
		case <-ctx.Done():
		}
	}
	if app != nil {
		app.shutdownNow()
	}
	metrics.reset()
	if server != nil {
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("stop browser proxy: %v", err)
			_ = server.Close()
		}
	}
	c.mu.Lock()
	c.server, c.listener, c.app = nil, nil, nil
	c.state = "stopped"
	c.runHash = ""
	c.gasKnown, c.gasConnected = true, false
	c.gasMessage = "Go proxy is stopped."
	if stopDone != nil {
		close(stopDone)
	}
	c.mu.Unlock()
	if server != nil {
		log.Printf("browser proxy stopped")
	}
}

func (c *proxyController) importCA(certBytes, keyBytes []byte) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != "" && c.state != "stopped" {
		return "", errors.New("stop the proxy before uploading a new CA")
	}
	if len(certBytes) == 0 || len(keyBytes) == 0 {
		return "", errors.New("select both the CA certificate and its matching private key")
	}
	if err := os.MkdirAll(c.caDir, 0700); err != nil {
		return "", fmt.Errorf("create CA directory: %w", err)
	}
	uploadDir, err := os.MkdirTemp(c.caDir, "uploaded-ca-")
	if err != nil {
		return "", fmt.Errorf("create uploaded CA directory: %w", err)
	}
	keepUpload := false
	defer func() {
		if !keepUpload {
			_ = os.RemoveAll(uploadDir)
		}
	}()
	_ = os.Chmod(uploadDir, 0700)
	certPath := filepath.Join(uploadDir, "ca.crt")
	keyPath := filepath.Join(uploadDir, "ca.key")
	if err := os.WriteFile(certPath, certBytes, 0600); err != nil {
		return "", fmt.Errorf("save CA certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		return "", fmt.Errorf("save CA private key: %w", err)
	}
	cert, _, _, _, err := loadOrCreateCA(uploadDir, certPath, keyPath)
	if err != nil {
		return "", fmt.Errorf("uploaded certificate/key pair is invalid: %w", err)
	}
	manifest, err := json.Marshal(struct {
		Directory string `json:"directory"`
	}{Directory: filepath.Base(uploadDir)})
	if err != nil {
		return "", fmt.Errorf("encode uploaded CA selection: %w", err)
	}
	if err := atomicWriteFile(filepath.Join(c.caDir, "uploaded-ca.json"), manifest, 0600); err != nil {
		return "", fmt.Errorf("save uploaded CA selection: %w", err)
	}
	c.caCertPath, c.caKeyPath, c.uploadedCAPath = certPath, keyPath, uploadDir
	c.caCertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keepUpload = true
	c.caUploaded = true
	c.caPath = certPath
	c.caFingerprint = fingerprintOf(cert)
	c.caExpires = cert.NotAfter
	c.caWarning = ""
	// Remove earlier uploaded pairs so old private keys do not pile up.
	if entries, readErr := os.ReadDir(c.caDir); readErr == nil {
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "uploaded-ca-") || entry.Name() == filepath.Base(uploadDir) {
				continue
			}
			old := filepath.Join(c.caDir, entry.Name())
			if filepath.Dir(old) == filepath.Clean(c.caDir) {
				_ = os.RemoveAll(old)
			}
		}
	}
	log.Printf("uploaded HTTPS interception CA pair from local browser selection: %s", certPath)
	return certPath, nil
}

func fingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func (c *proxyController) recordV2Ray(connected bool, message string) {
	c.mu.Lock()
	c.v2rayKnown, c.v2rayConnected, c.v2rayMessage = true, connected, message
	c.mu.Unlock()
}

func (c *proxyController) recordGAS(connected bool, message string) {
	c.mu.Lock()
	c.gasKnown, c.gasConnected, c.gasMessage = true, connected, message
	c.mu.Unlock()
}

func (c *proxyController) recordGASFrom(app *proxyApp, connected bool, message string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.app != app {
		return
	}
	c.gasKnown, c.gasConnected, c.gasMessage = true, connected, message
	if connected {
		c.v2rayKnown, c.v2rayConnected = true, true
		c.v2rayMessage = "Apps Script relay succeeded through V2RayNG."
	}
}

// activeCAPEM returns the CA certificate in use: the one loaded by the last
// start/upload, otherwise the one the next start would load (if it exists).
func (c *proxyController) activeCAPEM() []byte {
	c.mu.Lock()
	pemBytes := append([]byte(nil), c.caCertificate...)
	dir, certOverride, keyOverride := c.caDir, c.caCertPath, c.caKeyPath
	c.mu.Unlock()
	if len(pemBytes) > 0 {
		return pemBytes
	}
	certPath, _, _, err := resolveCAPaths(dir, certOverride, keyOverride)
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil
	}
	if block, _ := pem.Decode(data); block != nil {
		return pem.EncodeToMemory(block)
	}
	if cert, err := x509.ParseCertificate(data); err == nil {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	return nil
}

// regenerateCA replaces the default CA (ca.crt / ca.key) with a new pair. The
// old files are kept in ca-old-<timestamp>. It never runs automatically.
func (c *proxyController) regenerateCA() error {
	c.mu.Lock()
	if c.state != "" && c.state != "stopped" {
		c.mu.Unlock()
		return errors.New("stop the proxy before regenerating the CA")
	}
	if c.caCertPath != "" || c.caKeyPath != "" || c.caUploaded {
		c.mu.Unlock()
		return errors.New("only the default CA can be regenerated; a custom or uploaded CA is selected")
	}
	dir := c.caDir
	// Block Connect and uploads while the new key is generated.
	c.state = "starting"
	c.gen++
	myGen := c.gen
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.gen == myGen && c.state == "starting" {
			c.state = "stopped"
		}
		c.mu.Unlock()
	}()

	defaultCert := filepath.Join(dir, "ca.crt")
	defaultKey := filepath.Join(dir, "ca.key")
	active, _, _, err := resolveCAPaths(dir, "", "")
	if err != nil {
		return err
	}
	if filepath.Clean(active) != filepath.Clean(defaultCert) {
		return fmt.Errorf("the CA in use is %s, not the generated default; remove or rename it yourself", active)
	}
	backup := filepath.Join(dir, "ca-old-"+time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(backup, 0700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	var moved []string
	rollback := func() {
		_ = os.Remove(defaultCert)
		_ = os.Remove(defaultKey)
		for _, name := range moved {
			_ = os.Rename(filepath.Join(backup, name), filepath.Join(dir, name))
		}
		_ = os.Remove(backup)
	}
	for _, name := range []string{"ca.crt", "ca.key"} {
		if _, statErr := os.Stat(filepath.Join(dir, name)); statErr != nil {
			continue
		}
		if err := os.Rename(filepath.Join(dir, name), filepath.Join(backup, name)); err != nil {
			rollback()
			return fmt.Errorf("move old %s: %w", name, err)
		}
		moved = append(moved, name)
	}
	cert, _, certPath, _, err := loadOrCreateCA(dir, "", "")
	if err != nil {
		rollback()
		return fmt.Errorf("generate new CA: %w", err)
	}
	c.mu.Lock()
	c.caCertificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	c.caFingerprint = fingerprintOf(cert)
	c.caPath = certPath
	c.caExpires = cert.NotAfter
	c.caWarning = ""
	c.mu.Unlock()
	log.Printf("generated a new HTTPS interception CA at %s; the previous one is in %s", certPath, backup)
	return nil
}

func (c *proxyController) snapshot() controllerSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.state
	if state == "" {
		state = "stopped"
	}
	running := state == "running"
	snapshot := controllerSnapshot{
		State: state, Running: running,
		V2RayKnown: c.v2rayKnown, V2RayConnected: c.v2rayConnected, V2RayMessage: c.v2rayMessage,
		GASKnown: c.gasKnown, GASConnected: c.gasConnected, GASMessage: c.gasMessage,
		TestKnown: c.testKnown, TestOK: c.test.OK, TestMessage: c.test.Message,
		TestV2RayChecked: c.test.V2RayChecked, TestV2RayConnected: c.test.V2RayConnected,
		CAUploaded: c.caUploaded, CAFingerprint: c.caFingerprint, CAPath: c.caPath, CAWarning: c.caWarning,
	}
	if !c.caExpires.IsZero() {
		snapshot.CAExpires = c.caExpires.Format(time.RFC3339)
	}
	metricSnapshot := c.metrics.snapshot()
	snapshot.MetricKnown = metricSnapshot.Known
	snapshot.MetricConnected = metricSnapshot.Connected
	snapshot.ConnectionQuality = metricSnapshot.Quality
	snapshot.LatencyMS = metricSnapshot.LatencyMS
	snapshot.FullLatencyMS = metricSnapshot.FullLatencyMS
	snapshot.LatencyReady = metricSnapshot.LatencyReady
	snapshot.JitterMS = metricSnapshot.JitterMS
	snapshot.JitterReady = metricSnapshot.JitterReady
	snapshot.MetricSuccessRate = metricSnapshot.SuccessRate
	snapshot.MetricSampleCount = metricSnapshot.SampleCount
	snapshot.MetricFailureCount = metricSnapshot.FailureCount
	snapshot.MetricError = metricSnapshot.ErrorMessage
	snapshot.MetricUpdatedAt = metricSnapshot.UpdatedAt
	if !running {
		snapshot.ConnectionQuality = "DISCONNECTED"
		snapshot.MetricConnected = false
	} else if c.v2rayKnown && !c.v2rayConnected && !metricSnapshot.Connected && metricSnapshot.SampleCount == 0 {
		snapshot.ConnectionQuality = "BAD"
	}
	if c.listener != nil {
		snapshot.BrowserAddress = c.listener.Addr().String()
	}
	if c.app != nil {
		snapshot.BrowserLastSeen = c.app.lastBrowserSeen.Load()
		if snapshot.BrowserLastSeen > 0 && time.Since(time.UnixMilli(snapshot.BrowserLastSeen)) < 8*time.Second {
			snapshot.BrowserConnected = true
		}
		snapshot.SentRequests = c.app.sentRequests.Load()
		snapshot.SentBytes = c.app.sentBytes.Load()
		snapshot.ReceivedResponses = c.app.receivedResponses.Load()
		snapshot.ReceivedBytes = c.app.receivedBytes.Load()
		snapshot.GASRetries = c.app.retries.Load()
		snapshot.QueueMS = c.app.queueWaitMS.Load()
		snapshot.CertRejects = c.app.certRejects.Load()
	}
	return snapshot
}

func (s relaySettings) validateNetwork() error {
	if net.ParseIP(strings.TrimSpace(s.BrowserIP)) == nil || !isLoopback(strings.TrimSpace(s.BrowserIP)) {
		return errors.New("browser proxy bind IP must be a loopback IP such as 127.0.0.1 or ::1")
	}
	if s.BrowserPort < 1 || s.BrowserPort > 65535 {
		return errors.New("browser proxy port must be between 1 and 65535")
	}
	if err := s.validateV2Ray(); err != nil {
		return err
	}
	v2rayHost := strings.TrimSpace(s.V2RayIP)
	if (strings.EqualFold(v2rayHost, "localhost") || isLoopback(v2rayHost)) && s.V2RayPort == s.BrowserPort {
		return errors.New("browser proxy port must differ from the V2RayNG port")
	}
	return nil
}

func (s relaySettings) validate() error {
	if err := s.validateNetwork(); err != nil {
		return err
	}
	if err := s.validateGASURL(); err != nil {
		return err
	}
	if strings.TrimSpace(s.AuthKey) == "" {
		return errors.New("GAS AUTH_KEY is required")
	}
	return nil
}

func (s relaySettings) validateV2Ray() error {
	if strings.TrimSpace(s.V2RayIP) == "" {
		return errors.New("V2RayNG IP is required")
	}
	if strings.ContainsAny(s.V2RayIP, "/\\ \t\r\n") {
		return errors.New("V2RayNG address must be an IP or host name, without a scheme")
	}
	if s.V2RayPort < 1 || s.V2RayPort > 65535 {
		return errors.New("V2RayNG port must be between 1 and 65535")
	}
	if s.V2RayType != "http" && s.V2RayType != "socks5" {
		return errors.New("choose HTTP or SOCKS5 for the V2RayNG local inbound")
	}
	return nil
}

func (s relaySettings) validateGASURL() error {
	u, err := url.Parse(strings.TrimSpace(s.GASURL))
	if err != nil || u.Scheme != "https" || u.Host == "" || !strings.HasSuffix(u.Path, "/exec") {
		return errors.New("GAS URL must be an HTTPS Apps Script web app URL ending in /exec")
	}
	return nil
}

func newRelayHTTPClient(settings relaySettings, timeout time.Duration) (*http.Client, error) {
	proxyAddress := settings.v2rayAddress()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	// Keep more idle GAS connections ready for browsers that request many
	// resources at once. The default per-host pool of two causes avoidable
	// proxy and TLS handshakes on later requests.
	transport.MaxIdleConns = 128
	transport.MaxIdleConnsPerHost = 16
	transport.ForceAttemptHTTP2 = true
	if timeout == 0 {
		// Relay client: no overall deadline (large downloads), but fail if GAS
		// never starts answering.
		transport.ResponseHeaderTimeout = 90 * time.Second
	}
	if settings.V2RayType == "http" {
		proxyURL := &url.URL{Scheme: "http", Host: proxyAddress}
		transport.Proxy = http.ProxyURL(proxyURL)
	} else {
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return socks5DialContext(ctx, proxyAddress, address)
		}
	}
	return &http.Client{Timeout: timeout, Transport: transport}, nil
}

func lookupPublicIP(ctx context.Context, route string, settings relaySettings) (string, error) {
	var client *http.Client
	switch route {
	case "direct":
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp4", address)
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		client = &http.Client{Timeout: 8 * time.Second, Transport: transport}
	case "vpn":
		if err := settings.validateV2Ray(); err != nil {
			return "", fmt.Errorf("V2RayNG settings are invalid: %w", err)
		}
		var err error
		client, err = newRelayHTTPClient(settings, 8*time.Second)
		if err != nil {
			return "", fmt.Errorf("create V2RayNG transport: %w", err)
		}
	default:
		return "", errors.New("public IP route must be direct or vpn")
	}
	defer client.CloseIdleConnections()

	providers := []struct {
		name string
		url  string
	}{
		{name: "ipify", url: "https://api.ipify.org?format=json"},
		{name: "AWS checkip", url: "https://checkip.amazonaws.com/"},
		{name: "icanhazip", url: "https://ipv4.icanhazip.com/"},
	}
	failures := make([]string, 0, len(providers))
	for _, provider := range providers {
		attemptCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		request, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, provider.url, nil)
		if err != nil {
			cancel()
			failures = append(failures, provider.name+": create request: "+err.Error())
			continue
		}
		request.Header.Set("Accept", "application/json, text/plain")
		request.Header.Set("Cache-Control", "no-cache")
		response, err := client.Do(request)
		if err != nil {
			cancel()
			failures = append(failures, provider.name+": "+err.Error())
			continue
		}
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			_ = response.Body.Close()
			cancel()
			failures = append(failures, fmt.Sprintf("%s: HTTP %d", provider.name, response.StatusCode))
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		_ = response.Body.Close()
		cancel()
		if readErr != nil {
			failures = append(failures, provider.name+": read response: "+readErr.Error())
			continue
		}
		if len(data) > 4096 {
			failures = append(failures, provider.name+": response exceeded 4 KiB")
			continue
		}
		var result struct {
			IP string `json:"ip"`
		}
		ipText := strings.TrimSpace(string(data))
		if err := json.Unmarshal(data, &result); err == nil && strings.TrimSpace(result.IP) != "" {
			ipText = strings.TrimSpace(result.IP)
		}
		ip := net.ParseIP(ipText)
		if ip == nil {
			failures = append(failures, provider.name+": response did not contain a valid IP address")
			continue
		}
		return ip.String(), nil
	}
	return "", fmt.Errorf("public IP lookup through %s route failed at all providers: %s", route, strings.Join(failures, "; "))
}

func probeV2RayPort(settings relaySettings) error {
	conn, err := net.DialTimeout("tcp", settings.v2rayAddress(), 2*time.Second)
	if err != nil {
		return err
	}
	return conn.Close()
}

func socks5DialContext(ctx context.Context, proxyAddress, targetAddress string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		return nil, fmt.Errorf("dial SOCKS5 proxy %s: %w", proxyAddress, err)
	}
	keep := false
	// Closing the connection when ctx is cancelled unblocks the handshake
	// reads and writes below (needs Go 1.21 or newer).
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		if !keep {
			stop()
			_ = conn.Close()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return nil, fmt.Errorf("SOCKS5 greeting: %w", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return nil, fmt.Errorf("read SOCKS5 greeting: %w", err)
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		return nil, errors.New("SOCKS5 proxy rejected no-authentication mode")
	}
	host, portText, err := net.SplitHostPort(targetAddress)
	if err != nil {
		return nil, fmt.Errorf("parse SOCKS5 destination %q: %w", targetAddress, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid SOCKS5 destination port %q", portText)
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		request = append(request, 1)
		request = append(request, ip.To4()...)
	} else if ip := net.ParseIP(host); ip != nil {
		request = append(request, 4)
		request = append(request, ip.To16()...)
	} else {
		if len(host) > 255 {
			return nil, errors.New("SOCKS5 destination host exceeds 255 bytes")
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("send SOCKS5 connect request: %w", err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, fmt.Errorf("read SOCKS5 connect reply: %w", err)
	}
	if reply[0] != 5 {
		return nil, errors.New("invalid SOCKS5 reply version")
	}
	if reply[1] != 0 {
		return nil, fmt.Errorf("SOCKS5 connect failed with reply code %d", reply[1])
	}
	var addressLength int
	switch reply[3] {
	case 1:
		addressLength = 4
	case 4:
		addressLength = 16
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return nil, fmt.Errorf("read SOCKS5 bound host length: %w", err)
		}
		addressLength = int(size[0])
	default:
		return nil, errors.New("invalid SOCKS5 bound address type")
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addressLength+2)); err != nil {
		return nil, fmt.Errorf("read SOCKS5 bound address: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	if !stop() {
		return nil, ctx.Err()
	}
	keep = true
	return conn, nil
}

type gasTestResult struct {
	OK             bool    `json:"ok"`
	V2RayChecked   bool    `json:"v2rayChecked"`
	V2RayConnected bool    `json:"v2rayConnected"`
	GASChecked     bool    `json:"gasChecked"`
	GASReachable   bool    `json:"gasReachable"`
	LatencyMS      float64 `json:"latencyMs"`
	LatencyReady   bool    `json:"latencyReady"`
	Message        string  `json:"message"`
}

func testGAS(ctx context.Context, settings relaySettings) gasTestResult {
	if err := settings.validateV2Ray(); err != nil {
		message := "V2RayNG settings are invalid: " + err.Error()
		log.Printf("[test] %s", message)
		return gasTestResult{V2RayChecked: true, GASChecked: true, Message: message}
	}
	log.Printf("[test] checking V2RayNG %s (%s)", settings.v2rayAddress(), settings.V2RayType)
	if err := probeV2RayPort(settings); err != nil {
		message := fmt.Sprintf("V2RayNG is not reachable at %s: %v", settings.v2rayAddress(), err)
		log.Printf("[test] %s", message)
		return gasTestResult{V2RayChecked: true, Message: message}
	}
	checked := gasTestResult{V2RayChecked: true, V2RayConnected: true}
	if err := settings.validateGASURL(); err != nil {
		message := "V2RayNG local port is reachable, but the GAS URL is invalid: " + err.Error()
		log.Printf("[test] %s", message)
		checked.GASChecked, checked.Message = true, message
		return checked
	}
	if strings.TrimSpace(settings.AuthKey) == "" {
		message := "V2RayNG local port is reachable; enter GAS AUTH_KEY to test the Apps Script connection."
		log.Printf("[test] %s", message)
		checked.GASChecked, checked.Message = true, message
		return checked
	}
	client, err := newRelayHTTPClient(settings, 25*time.Second)
	if err != nil {
		message := "could not create V2RayNG transport: " + err.Error()
		log.Printf("[test] %s", message)
		return checkedWithGASFailure(checked, message)
	}
	// testGAS builds a fresh transport every call; without this, each "Test
	// GAS" click leaks a new set of idle connections to V2RayNG/GAS.
	defer client.CloseIdleConnections()
	// A relayed GET that must come back 204 exercises the whole path
	// (GAS -> Worker -> internet -> back), not just the AUTH_KEY check.
	const probeURL = "https://www.gstatic.com/generate_204"
	probePayload, err := json.Marshal(relayRequest{
		Key: settings.AuthKey, URL: probeURL, Method: http.MethodGet,
		Headers: map[string]string{"Accept-Encoding": "identity"}, Redirect: false,
	})
	if err != nil {
		return checkedWithGASFailure(checked, "could not encode GAS test request: "+err.Error())
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(settings.GASURL), bytes.NewReader(probePayload))
	if err != nil {
		return checkedWithGASFailure(checked, "invalid GAS URL: "+err.Error())
	}
	request.Header.Set("Content-Type", "application/json")
	log.Printf("[test] relaying GET %s through V2RayNG -> GAS -> Worker", probeURL)
	startedAt := time.Now()
	response, err := client.Do(request)
	if err != nil {
		message := "V2RayNG port is reachable, but the request to GAS failed: " + err.Error()
		log.Printf("[test] %s", message)
		return checkedWithGASFailure(checked, message)
	}
	latency := time.Since(startedAt)
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if readErr != nil {
		message := "GAS responded, but reading its response failed: " + readErr.Error()
		log.Printf("[test] %s", message)
		return withGASLatency(checkedWithGASFailure(checked, message), latency)
	}
	var body relayResponse
	if err := json.Unmarshal(data, &body); err != nil {
		message := fmt.Sprintf("GAS is reachable (HTTP %d), but returned non-relay data: %.240s", response.StatusCode, strings.TrimSpace(string(data)))
		log.Printf("[test] %s", message)
		return withGASLatency(checkedWithGASResponse(checked, true, message), latency)
	}
	if strings.EqualFold(body.Error, "unauthorized") {
		message := "GAS is reachable through V2RayNG, but it rejected AUTH_KEY. Check that it matches Code.gs."
		log.Printf("[test] %s", message)
		return withGASLatency(checkedWithGASResponse(checked, true, message), latency)
	}
	if body.Error != "" {
		message := fmt.Sprintf("GAS accepted AUTH_KEY, but the relayed request failed: %.240s", body.Error)
		log.Printf("[test] %s", message)
		return withGASLatency(checkedWithGASResponse(checked, true, message), latency)
	}
	log.Printf("[test] relayed GET generate_204 -> HTTP %d, %d Set-Cookie header(s), %d header(s) total, %.0f ms",
		body.Status, body.Headers.count("set-cookie"), len(body.Headers), float64(latency)/float64(time.Millisecond))
	if body.Status == http.StatusNoContent {
		message := fmt.Sprintf("Test passed: a relayed GET to gstatic.com returned 204 in %.0f ms, so GAS and the Worker both work.", float64(latency)/float64(time.Millisecond))
		log.Printf("[test] %s", message)
		return withGASLatency(checkedWithGASResponse(checked, true, message, true), latency)
	}
	message := fmt.Sprintf("GAS is reachable and AUTH_KEY was accepted, but the relayed GET to gstatic.com returned HTTP %d instead of 204. Check the Worker URL/secret in Code.gs.", body.Status)
	log.Printf("[test] %s", message)
	return withGASLatency(checkedWithGASResponse(checked, true, message), latency)
}

func withGASLatency(result gasTestResult, duration time.Duration) gasTestResult {
	result.LatencyMS = float64(duration) / float64(time.Millisecond)
	result.LatencyReady = true
	return result
}

func checkedWithGASFailure(result gasTestResult, message string) gasTestResult {
	result.GASChecked = true
	result.GASReachable = false
	result.Message = message
	return result
}

func checkedWithGASResponse(result gasTestResult, reachable bool, message string, accepted ...bool) gasTestResult {
	result.GASChecked = true
	result.GASReachable = reachable
	result.Message = message
	if len(accepted) > 0 {
		result.OK = accepted[0]
	}
	return result
}

type clientUI struct {
	mu              sync.RWMutex
	defaults        relaySettings
	defaultGASURL   string
	defaultAuthKey  string
	profiles        []gasProfile
	activeProfileID string
	// settingsLocked is set when the settings file existed but could not be
	// read at startup; saving is then refused so profiles are not overwritten.
	settingsLocked error
	controller     *proxyController
	logs           *logBuffer
	guiAddress     string
	probeToken     string
	settingsFile   string
	quit           chan struct{}
}

func profileChoices(defaultGASURL, defaultAuthKey string, profiles []gasProfile) []gasProfile {
	choices := make([]gasProfile, 0, len(profiles)+1)
	choices = append(choices, gasProfile{
		ID: builtInProfileID, Name: "Built-in default",
		GASURL: defaultGASURL, AuthKey: defaultAuthKey,
	})
	return append(choices, profiles...)
}

func (ui *clientUI) writeSavedState(settings relaySettings, profiles []gasProfile, activeProfileID string) error {
	if ui.settingsLocked != nil {
		return fmt.Errorf("saved settings were unreadable at startup (%v); fix the file and restart so profiles aren't overwritten", ui.settingsLocked)
	}
	savedSettings := settings
	savedSettings.AuthKey = ""
	state := savedGUIState{
		Version: 2, Settings: savedSettings, Profiles: append([]gasProfile(nil), profiles...),
		ActiveProfileID: activeProfileID,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode saved settings and GAS profiles: %w", err)
	}
	if dir := filepath.Dir(ui.settingsFile); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create settings directory: %w", err)
		}
	}
	// Write atomically: a crash or power loss mid-write must never leave a
	// truncated/corrupt settings file that silently drops saved profiles.
	tmp, err := os.CreateTemp(filepath.Dir(ui.settingsFile), ".gas-proxy-settings-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp settings file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write settings and GAS profiles: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("flush settings and GAS profiles: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp settings file: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0600); err != nil {
			return fmt.Errorf("restrict saved settings permissions: %w", err)
		}
	}
	if err := os.Rename(tmpPath, ui.settingsFile); err != nil {
		return fmt.Errorf("save settings and GAS profiles: %w", err)
	}
	return nil
}

func (ui *clientUI) saveProfile(settings relaySettings, name, id string) (gasProfile, []gasProfile, string, error) {
	settings.GASURL = strings.TrimSpace(settings.GASURL)
	settings.AuthKey = strings.TrimSpace(settings.AuthKey)
	if err := settings.validateGASURL(); err != nil {
		return gasProfile{}, nil, "", err
	}
	if settings.AuthKey == "" {
		return gasProfile{}, nil, "", errors.New("GAS AUTH_KEY is required to save this profile")
	}

	ui.mu.Lock()
	defer ui.mu.Unlock()
	profiles := append([]gasProfile(nil), ui.profiles...)
	profileIndex := -1
	if id != "" && id != builtInProfileID {
		for i := range profiles {
			if profiles[i].ID == id {
				profileIndex = i
				break
			}
		}
	}
	if profileIndex < 0 && id == "" {
		for i := range profiles {
			if profiles[i].GASURL == settings.GASURL && profiles[i].AuthKey == settings.AuthKey {
				profileIndex = i
				break
			}
		}
	}
	profile := gasProfile{GASURL: settings.GASURL, AuthKey: settings.AuthKey, Name: strings.TrimSpace(name)}
	if profileIndex >= 0 {
		profile.ID = profiles[profileIndex].ID
	} else {
		id, err := randomToken()
		if err != nil {
			return gasProfile{}, nil, "", fmt.Errorf("create GAS profile identifier: %w", err)
		}
		profile.ID = id
	}
	if profile.Name == "" {
		if profileIndex >= 0 {
			profile.Name = profiles[profileIndex].Name
		} else {
			profile.Name = fmt.Sprintf("GAS profile %d", len(profiles)+1)
		}
	}
	if profileIndex >= 0 {
		profiles[profileIndex] = profile
	} else {
		profiles = append(profiles, profile)
	}
	// Only the GAS fields change here; the saved network fields stay as they
	// were (they have their own validated endpoint, saveNetwork).
	next := ui.defaults
	next.GASURL, next.AuthKey = settings.GASURL, settings.AuthKey
	if err := ui.writeSavedState(next, profiles, profile.ID); err != nil {
		return gasProfile{}, nil, "", err
	}
	ui.defaults = next
	ui.profiles = profiles
	ui.activeProfileID = profile.ID
	return profile, profileChoices(ui.defaultGASURL, ui.defaultAuthKey, profiles), profile.ID, nil
}

func (ui *clientUI) selectProfile(id string) (gasProfile, []gasProfile, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	var selected gasProfile
	if id == builtInProfileID {
		selected = gasProfile{ID: builtInProfileID, Name: "Built-in default", GASURL: ui.defaultGASURL, AuthKey: ui.defaultAuthKey}
	} else {
		var ok bool
		selected, ok = findProfile(ui.profiles, id)
		if !ok {
			return gasProfile{}, nil, errors.New("selected GAS profile no longer exists")
		}
	}
	settings := ui.defaults
	settings.GASURL, settings.AuthKey = selected.GASURL, selected.AuthKey
	if err := ui.writeSavedState(settings, ui.profiles, selected.ID); err != nil {
		return gasProfile{}, nil, err
	}
	ui.defaults, ui.activeProfileID = settings, selected.ID
	return selected, profileChoices(ui.defaultGASURL, ui.defaultAuthKey, ui.profiles), nil
}

func (ui *clientUI) deleteProfile(id string) (gasProfile, []gasProfile, string, error) {
	if id == builtInProfileID {
		return gasProfile{}, nil, "", errors.New("the built-in GAS profile cannot be deleted")
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	profiles := make([]gasProfile, 0, len(ui.profiles))
	found := false
	for _, profile := range ui.profiles {
		if profile.ID == id {
			found = true
			continue
		}
		profiles = append(profiles, profile)
	}
	if !found {
		return gasProfile{}, nil, "", errors.New("selected GAS profile no longer exists")
	}
	activeID := ui.activeProfileID
	settings := ui.defaults
	if activeID == id {
		activeID = builtInProfileID
		settings.GASURL, settings.AuthKey = ui.defaultGASURL, ui.defaultAuthKey
	}
	if err := ui.writeSavedState(settings, profiles, activeID); err != nil {
		return gasProfile{}, nil, "", err
	}
	ui.defaults, ui.profiles, ui.activeProfileID = settings, profiles, activeID
	activeProfile, _ := findProfile(profileChoices(ui.defaultGASURL, ui.defaultAuthKey, profiles), activeID)
	return activeProfile, profileChoices(ui.defaultGASURL, ui.defaultAuthKey, profiles), activeID, nil
}

func (ui *clientUI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !localRequestHost(r.Host) {
		http.Error(w, "GUI accepts loopback requests only", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ui.servePage(w)
	case "/api/status":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ui.writeJSON(w, ui.controller.snapshot())
	case "/api/logs":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ui.writeJSON(w, map[string]any{"lines": ui.logs.snapshot()})
	case "/api/public-ip":
		if !ui.requireJSONPost(w, r) {
			return
		}
		var request struct {
			Route     string `json:"route"`
			V2RayIP   string `json:"v2rayIP"`
			V2RayPort int    `json:"v2rayPort"`
			V2RayType string `json:"v2rayType"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request); err != nil {
			ui.writeJSONError(w, http.StatusBadRequest, "invalid public IP lookup request")
			return
		}
		if request.Route != "direct" && request.Route != "vpn" {
			ui.writeJSONError(w, http.StatusBadRequest, "public IP route must be direct or vpn")
			return
		}
		settings := relaySettings{V2RayIP: request.V2RayIP, V2RayPort: request.V2RayPort, V2RayType: request.V2RayType}
		if request.Route == "vpn" {
			if err := settings.validateV2Ray(); err != nil {
				ui.writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 9*time.Second)
		defer cancel()
		ip, err := lookupPublicIP(ctx, request.Route, settings)
		if err != nil {
			log.Printf("[public-ip] %s lookup failed: %v", request.Route, err)
			ui.writeJSONError(w, http.StatusBadGateway, err.Error())
			return
		}
		ui.writeJSON(w, map[string]any{
			"ok": true, "route": request.Route, "ip": ip,
			"checkedAt": time.Now().Format(time.RFC3339),
		})
	case "/api/ui-log":
		if !ui.requireJSONPost(w, r) {
			return
		}
		var report struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&report); err != nil {
			http.Error(w, "invalid GUI log message", http.StatusBadRequest)
			return
		}
		message := strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(report.Message))
		if message == "" {
			http.Error(w, "GUI log message is empty", http.StatusBadRequest)
			return
		}
		if len(message) > 1200 {
			message = message[:1200]
		}
		log.Printf("[GUI] %s", message)
		ui.writeJSON(w, map[string]any{"ok": true})
	case "/api/profiles/save":
		if !ui.requireJSONPost(w, r) {
			return
		}
		var request struct {
			ID       string        `json:"id"`
			Name     string        `json:"name"`
			Settings relaySettings `json:"settings"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&request); err != nil {
			ui.writeJSONError(w, http.StatusBadRequest, "invalid GAS profile data")
			return
		}
		profile, profiles, activeID, err := ui.saveProfile(request.Settings, request.Name, request.ID)
		if err != nil {
			log.Printf("[profiles] save failed: %v", err)
			ui.writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		ui.writeJSON(w, map[string]any{
			"ok": true, "message": "GAS profile saved.", "profile": profile,
			"profiles": profiles, "activeProfileID": activeID,
		})
	case "/api/profiles/select":
		if !ui.requireJSONPost(w, r) {
			return
		}
		var request struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request); err != nil {
			ui.writeJSONError(w, http.StatusBadRequest, "invalid GAS profile selection")
			return
		}
		profile, profiles, err := ui.selectProfile(request.ID)
		if err != nil {
			log.Printf("[profiles] selection failed: %v", err)
			ui.writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		ui.writeJSON(w, map[string]any{
			"ok": true, "profile": profile, "profiles": profiles,
			"activeProfileID": profile.ID,
		})
	case "/api/profiles/delete":
		if !ui.requireJSONPost(w, r) {
			return
		}
		var request struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request); err != nil {
			ui.writeJSONError(w, http.StatusBadRequest, "invalid GAS profile selection")
			return
		}
		profile, profiles, activeID, err := ui.deleteProfile(request.ID)
		if err != nil {
			log.Printf("[profiles] delete failed: %v", err)
			ui.writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		ui.writeJSON(w, map[string]any{
			"ok": true, "message": "GAS profile deleted.", "profile": profile,
			"profiles": profiles, "activeProfileID": activeID,
		})
	case "/api/ca/regenerate":
		if !ui.requireJSONPost(w, r) {
			return
		}
		if err := ui.controller.regenerateCA(); err != nil {
			log.Printf("[certificate] regenerate failed: %v", err)
			ui.writeJSON(w, map[string]any{"ok": false, "message": err.Error()})
			return
		}
		ui.writeJSON(w, map[string]any{"ok": true, "message": "New CA generated. The old one was kept in a ca-old folder. Import the new certificate into your browser."})
	case "/api/settings/save":
		if !ui.requireJSONPost(w, r) {
			return
		}
		var network relaySettings
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&network); err != nil {
			ui.writeJSONError(w, http.StatusBadRequest, "invalid settings JSON")
			return
		}
		if err := ui.saveNetwork(network); err != nil {
			log.Printf("[settings] save failed: %v", err)
			ui.writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		ui.writeJSON(w, map[string]any{"ok": true})
	case "/api/ca-cert":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		certificate := ui.controller.activeCAPEM()
		if len(certificate) == 0 {
			http.Error(w, "start the proxy once to generate the CA", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="medovpn-ca.crt"`)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(certificate)
	case "/api/start":
		if !ui.requireJSONPost(w, r) {
			return
		}
		settings, ok := ui.readSettings(w, r)
		if !ok {
			return
		}
		address, caPath, err := ui.controller.start(settings, ui.guiAddress, ui.probeToken, ui)
		if err != nil {
			log.Printf("[run] failed: %v", err)
			var se *startError
			if errors.As(err, &se) {
				switch se.component {
				case "v2ray":
					ui.controller.recordV2Ray(false, err.Error())
				case "gas":
					ui.controller.recordGAS(false, err.Error())
				}
			}
			ui.writeJSON(w, map[string]any{"ok": false, "message": err.Error()})
			return
		}
		// Starting must never overwrite the saved GAS fields, so only the
		// validated network fields are persisted here.
		saveErr := ui.saveNetwork(settings)
		if saveErr != nil {
			log.Printf("[settings] could not save settings: %v", saveErr)
		}
		message := fmt.Sprintf("Go proxy is listening at %s. Import the CA certificate at %s into Firefox for HTTPS.", address, caPath)
		started := map[string]any{"ok": true, "message": message, "persisted": saveErr == nil}
		if saveErr != nil {
			started["persistError"] = saveErr.Error()
		}
		ui.writeJSON(w, started)
	case "/api/stop":
		if !ui.requireJSONPost(w, r) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		ui.controller.stop(ctx)
		ui.writeJSON(w, map[string]any{"ok": true, "message": "Go proxy stopped."})
	case "/api/quit":
		if !ui.requireJSONPost(w, r) {
			return
		}
		ui.writeJSON(w, map[string]any{"ok": true, "message": "MedoVPN is closing."})
		time.AfterFunc(200*time.Millisecond, func() {
			select {
			case ui.quit <- struct{}{}:
			default:
			}
		})
	case "/api/test":
		if !ui.requireJSONPost(w, r) {
			return
		}
		settings, ok := ui.readSettings(w, r)
		if !ok {
			return
		}
		result := testGAS(r.Context(), settings)
		ui.controller.recordTest(result)
		ui.writeJSON(w, result)
	case "/api/config-match":
		if !ui.requireJSONPost(w, r) {
			return
		}
		settings, ok := ui.readSettings(w, r)
		if !ok {
			return
		}
		running, match := ui.controller.configMatch(settings)
		ui.writeJSON(w, map[string]any{"running": running, "match": match})
	case "/api/upload-ca":
		if r.Method != http.MethodPost || !ui.sameOrigin(r) {
			http.Error(w, "same-origin POST required", http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data;") {
			http.Error(w, "multipart/form-data required", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 12<<20)
		if err := r.ParseMultipartForm(12 << 20); err != nil {
			http.Error(w, "certificate upload is too large or invalid", http.StatusBadRequest)
			return
		}
		certBytes, err := readUploadedFile(r, "caCert", 5<<20)
		if err != nil {
			ui.writeJSON(w, map[string]any{"ok": false, "message": "CA certificate: " + err.Error()})
			return
		}
		keyBytes, err := readUploadedFile(r, "caKey", 5<<20)
		if err != nil {
			ui.writeJSON(w, map[string]any{"ok": false, "message": "CA private key: " + err.Error()})
			return
		}
		path, err := ui.controller.importCA(certBytes, keyBytes)
		if err != nil {
			log.Printf("[certificate] upload failed: %v", err)
			ui.writeJSON(w, map[string]any{"ok": false, "message": err.Error()})
			return
		}
		ui.writeJSON(w, map[string]any{"ok": true, "message": "CA pair uploaded and validated. Go will use it when the proxy starts.", "path": path})
	case "/api/browser-log":
		if !ui.requireJSONPost(w, r) {
			return
		}
		var report struct {
			State string `json:"state"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&report); err != nil {
			http.Error(w, "invalid browser report", http.StatusBadRequest)
			return
		}
		if report.State == "connected" {
			log.Printf("[browser] browser reached the Go proxy at %s", ui.controller.snapshot().BrowserAddress)
		} else if report.State == "disconnected" {
			log.Printf("[browser] browser has not reached the Go proxy; set its HTTP and HTTPS proxy to the displayed browser address")
		}
		ui.writeJSON(w, map[string]any{"ok": true})
	default:
		http.NotFound(w, r)
	}
}

// saveNetwork validates and persists only the browser/V2RayNG address fields.
func (ui *clientUI) saveNetwork(s relaySettings) error {
	s.BrowserIP = strings.TrimSpace(s.BrowserIP)
	s.V2RayIP = strings.TrimSpace(s.V2RayIP)
	if err := s.validateNetwork(); err != nil {
		return err
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	next := ui.defaults
	next.BrowserIP, next.BrowserPort = s.BrowserIP, s.BrowserPort
	next.V2RayIP, next.V2RayPort, next.V2RayType = s.V2RayIP, s.V2RayPort, s.V2RayType
	if err := ui.writeSavedState(next, ui.profiles, ui.activeProfileID); err != nil {
		return err
	}
	ui.defaults = next
	return nil
}

func (ui *clientUI) requireJSONPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !ui.sameOrigin(r) {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return false
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

func (ui *clientUI) sameOrigin(r *http.Request) bool {
	origin, err := url.Parse(r.Header.Get("Origin"))
	return err == nil && origin.Scheme == "http" && strings.EqualFold(origin.Host, r.Host)
}

func readUploadedFile(r *http.Request, field string, maxBytes int64) ([]byte, error) {
	file, _, err := r.FormFile(field)
	if err != nil {
		return nil, errors.New("choose a file")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errors.New("file exceeds 5 MiB")
	}
	return data, nil
}

func (ui *clientUI) readSettings(w http.ResponseWriter, r *http.Request) (relaySettings, bool) {
	var settings relaySettings
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&settings); err != nil {
		http.Error(w, "invalid settings JSON", http.StatusBadRequest)
		return relaySettings{}, false
	}
	settings.AuthKey = strings.TrimSpace(settings.AuthKey)
	settings.GASURL = strings.TrimSpace(settings.GASURL)
	return settings, true
}

func (ui *clientUI) writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func (ui *clientUI) writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "message": message})
}

func (ui *clientUI) servePage(w http.ResponseWriter) {
	ui.mu.RLock()
	defaults := ui.defaults
	profiles := profileChoices(ui.defaultGASURL, ui.defaultAuthKey, ui.profiles)
	activeProfileID := ui.activeProfileID
	ui.mu.RUnlock()
	boot, err := json.Marshal(map[string]any{
		"settings":        defaults,
		"probeToken":      ui.probeToken,
		"profiles":        profiles,
		"activeProfileID": activeProfileID,
	})
	if err != nil {
		http.Error(w, "cannot prepare GUI", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' http://gas-proxy-check.invalid; script-src 'unsafe-inline'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	_, _ = io.WriteString(w, strings.Replace(dashboardHTML, "__BOOT_DATA__", string(boot), 1))
}

func localRequestHost(hostport string) bool {
	host := hostport
	if parsed, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsed
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func randomToken() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func openSystemBrowser(address string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", address)
	case "darwin":
		cmd = exec.Command("open", address)
	default:
		cmd = exec.Command("xdg-open", address)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("open GUI browser failed (%v); open %s manually", err, address)
		return
	}
	go func() { _ = cmd.Wait() }()
}

const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MedoVPN</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2d;--panel2:#17223a;--line:#283653;--muted:#95a3bd;--text:#edf3ff;--green:#31d49a;--red:#ff647c;--amber:#f5be55;--blue:#75a7ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 85% 0,#17294b 0,transparent 38%),var(--bg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--text)}main{max-width:1120px;margin:0 auto;padding:32px 22px 46px}.top{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:24px}.brand{display:flex;align-items:center;gap:14px}.logo{width:44px;height:44px;border:1px solid #37517d;border-radius:14px;display:grid;place-items:center;background:#162544;color:#8ab4ff;font-weight:800;font-size:18px;box-shadow:0 8px 28px #0005}.brand h1{font-size:23px;line-height:1.2;margin:0}.brand p{margin:5px 0 0;color:var(--muted);font-size:13px}.tag{border:1px solid var(--line);background:#111a2b;color:#b9c9e4;padding:7px 11px;border-radius:99px;font-size:12px;white-space:nowrap}.grid{display:grid;grid-template-columns:1.35fr .85fr;gap:16px}.card{background:linear-gradient(145deg,#141e33,#101827);border:1px solid var(--line);border-radius:16px;padding:19px;box-shadow:0 14px 35px #0002}.card h2{font-size:16px;margin:0 0 14px;letter-spacing:.01em}.section-note,.hint{color:var(--muted);font-size:12px}.form-grid{display:grid;grid-template-columns:1fr 135px;gap:12px}.field{display:flex;flex-direction:column;gap:6px}.field label{font-size:12px;color:#bac7db}.field input,.field select{width:100%;height:42px;background:#0b1322;border:1px solid #344462;border-radius:9px;padding:0 11px;color:var(--text);outline:none}.field input:focus,.field select:focus{border-color:var(--blue);box-shadow:0 0 0 3px #75a7ff22}.field input[type=password]{letter-spacing:.06em}.secret-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px}.secret-row .btn{min-width:76px;padding:8px 12px}.profile-actions{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:8px}.profile-actions .btn{padding:8px 12px;white-space:nowrap}.field.full{grid-column:1/-1}.v2ray-row{display:grid;grid-template-columns:1fr 125px 145px;gap:10px}.status-grid{display:grid;gap:11px}.status-row{padding:13px 14px;background:#0e1727;border:1px solid #253450;border-radius:11px;display:flex;justify-content:space-between;align-items:center;gap:12px}.status-name{display:flex;align-items:center;gap:10px;font-weight:650}.status-detail{color:var(--muted);font-size:12px;text-align:right;max-width:60%;overflow-wrap:anywhere}.dot{width:11px;height:11px;border-radius:50%;background:#71809a;box-shadow:0 0 0 4px #71809a20;flex:0 0 auto}.dot.ok{background:var(--green);box-shadow:0 0 0 4px #31d49a20,0 0 14px #31d49a55}.dot.bad{background:var(--red);box-shadow:0 0 0 4px #ff647c20}.dot.wait{background:var(--amber);box-shadow:0 0 0 4px #f5be5520}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}.btn{border:0;border-radius:9px;padding:10px 16px;font-weight:700;color:#07121d;background:var(--green);cursor:pointer;min-height:41px}.btn:hover{filter:brightness(1.08)}.btn:disabled{opacity:.52;cursor:wait}.btn.secondary{background:#263651;color:#dce8fb;border:1px solid #3b4d6b}.btn.stop{background:#4a2030;color:#ffdce3;border:1px solid #7e3449}.btn.test{background:#294a78;color:#edf4ff;border:1px solid #436ca5}.btnlink{text-decoration:none;display:inline-flex;align-items:center}.test-result{font-size:13px;margin-top:12px;min-height:20px;color:var(--muted)}.test-result.ok{color:var(--green)}.test-result.bad{color:var(--red)}.wide{grid-column:1/-1}.flow-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.flow-card{padding:16px;background:#0d1626;border:1px solid #273955;border-radius:13px;transition:border-color .2s,box-shadow .2s}.flow-card.flash{border-color:#65a1ff;box-shadow:0 0 0 2px #65a1ff33,0 0 25px #4f8de733}.flow-title{font-size:12px;text-transform:uppercase;letter-spacing:.09em;color:#9eb5d8;font-weight:750}.route{display:flex;align-items:center;justify-content:space-between;gap:7px;margin:17px 0 13px}.node{font-size:12px;font-weight:650;background:#192640;border:1px solid #334768;border-radius:8px;padding:8px 9px;text-align:center;white-space:nowrap}.arrow{color:#6685b1;font-size:21px;font-weight:800;transition:color .15s,transform .15s}.flow-card.flash .arrow{color:var(--green);transform:translateX(2px)}.flow-card.receive.flash .arrow{color:var(--blue);transform:translateX(-2px)}.flow-health{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:11px 0 12px;min-height:28px}.quality-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid #3a4b68;border-radius:999px;padding:4px 9px;color:#c3cee0;font-size:10px;font-weight:800;letter-spacing:.08em}.quality-pill:before{content:"";width:7px;height:7px;border-radius:50%;background:#71809a}.quality-pill.good{color:var(--green);border-color:#267859;background:#102a25}.quality-pill.good:before{background:var(--green);box-shadow:0 0 10px #31d49a77}.quality-pill.normal{color:var(--amber);border-color:#705b30;background:#2a2418}.quality-pill.normal:before{background:var(--amber)}.quality-pill.bad{color:var(--red);border-color:#713648;background:#2a1720}.quality-pill.bad:before{background:var(--red)}.quality-pill.disconnected{color:#a7b1c2}.flow-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px;color:var(--muted);font-size:12px}.flow-stats span{background:#111d31;border:1px solid #243450;border-radius:9px;padding:9px 10px}.flow-stats strong{display:block;color:var(--text);font-size:14px;margin-bottom:2px}.metric-line{font-size:10px;text-align:right;overflow-wrap:anywhere}.cert-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.cert-picker{background:#0b1322;border:1px dashed #415578;border-radius:10px;padding:11px}.cert-picker label{display:block;color:#b9c7dd;font-size:12px;margin-bottom:7px}.cert-picker input{width:100%;font-size:12px;color:var(--muted)}.cert-info{margin:10px 0 0}.logs{height:190px;overflow:auto;background:#080e19;border:1px solid #26344c;border-radius:10px;padding:12px;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;color:#b8c8df}.logs .empty{color:#66758d}.log-card{margin-top:16px}.bottom-note{color:#73839e;font-size:11px;margin-top:16px}.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px}.small{font-size:11px;color:var(--muted)}@media(max-width:800px){.grid{grid-template-columns:1fr}.wide{grid-column:auto}.flow-grid{grid-template-columns:1fr}.status-detail{max-width:55%}}@media(max-width:520px){main{padding:20px 13px}.top{align-items:flex-start}.tag{display:none}.v2ray-row{grid-template-columns:1fr 100px}.v2ray-row .type{grid-column:1/-1}.profile-actions{grid-template-columns:1fr 1fr}.profile-actions select{grid-column:1/-1}.cert-row{grid-template-columns:1fr}.route{gap:4px}.node{font-size:10px;padding:7px 5px}.arrow{font-size:16px}.flow-stats{grid-template-columns:repeat(2,minmax(0,1fr))}.flow-stats span:last-child{grid-column:1/-1}}
</style>
<style>
.global-card{margin:0 0 16px;border-color:#38577f;background:linear-gradient(145deg,#172844,#111b2d)}.global-card h2{margin-bottom:5px}.global-card .section-note{margin:0}.global-card .actions{margin-top:13px}
.grid{grid-template-columns:1fr;gap:16px}.wide{grid-column:auto}.component-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.component-card{min-width:0;padding:15px;background:#0d1626;border:1px solid #273955;border-radius:13px}.component-card h3{font-size:14px;margin:0 0 12px;color:#e9f0fc}.component-card .form-grid{grid-template-columns:minmax(0,1fr) 100px;gap:9px}.component-card .field.full{grid-column:1/-1}.component-card .v2ray-row{grid-template-columns:minmax(0,1fr) 82px}.component-card .v2ray-row .type{grid-column:1/-1}.component-card .actions,.component-actions{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px}.component-card .btn{padding:8px 11px;min-height:38px;font-size:12px}.component-state{font-size:12px;color:var(--muted);min-height:19px;margin-top:9px;overflow-wrap:anywhere}
.route-card{margin-top:14px;padding:15px;background:#0b1423;border:1px solid #263955;border-radius:12px}.route-card h3{margin:0 0 10px;font-size:13px;color:#bacbe5}.route-line{display:flex;align-items:center;justify-content:center;gap:12px;flex-wrap:wrap}.route-node{padding:8px 14px;border:1px solid #713648;border-radius:9px;background:#251620;color:var(--red);font-size:13px;font-weight:750;transition:.2s}.route-node.ok{color:var(--green);border-color:#267859;background:#102a25;box-shadow:0 0 12px #31d49a22}.route-node.wait{color:var(--amber);border-color:#705b30;background:#2a2418}.route-arrow{font-size:20px;color:#6685b1;font-weight:800}
.traffic-dials{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.dial-card{padding:14px;background:#0d1626;border:1px solid #273955;border-radius:13px;text-align:center}.dial-title{font-size:13px;color:#bacbe5;font-weight:750}.dial-svg{display:block;width:min(100%,270px);height:auto;margin:0 auto -8px;overflow:visible}.dial-track{fill:none;stroke:#293d5c;stroke-width:12;stroke-linecap:round}.dial-tick{stroke:#8296b4;stroke-width:2;opacity:.72}.dial-needle{stroke:#61a5ff;stroke-width:4;stroke-linecap:round;filter:drop-shadow(0 0 4px #61a5ff88);transition:transform .5s ease}.dial-needle.receive{stroke:#31d49a;filter:drop-shadow(0 0 4px #31d49a88)}.dial-center{fill:#e8f0ff;stroke:#101827;stroke-width:4}.dial-speed{font-size:20px;font-weight:800;color:var(--text);font-variant-numeric:tabular-nums}.dial-caption{font-size:11px;color:var(--muted);margin-top:2px}.traffic-meta{margin-top:14px}.cert-status{min-width:190px}.cert-status.missing{background:#4a2030;color:#ffdce3;border:1px solid #7e3449}.cert-status.uploaded{background:#123b30;color:#d4ffef;border:1px solid #267859}.log-card{margin-top:16px}
@media(max-width:900px){.component-grid{grid-template-columns:1fr 1fr}.component-card:last-child{grid-column:1/-1}}
@media(max-width:620px){.component-grid,.traffic-dials{grid-template-columns:1fr}.component-card:last-child{grid-column:auto}.component-card .form-grid{grid-template-columns:minmax(0,1fr) 90px}.route-line{gap:7px}.route-node{padding:7px 10px;font-size:12px}.route-arrow{font-size:16px}}
/* Premium instrument-panel finish */
:root{--bg:#070b16;--panel:#101829;--line:#273852;--muted:#91a3bf;--text:#f0f5ff;--green:#39e0aa;--red:#ff5577;--blue:#6eafff;--cyan:#69e5ff}
body{min-height:100vh;background:radial-gradient(ellipse at 16% -8%,#18355899 0,transparent 36%),radial-gradient(ellipse at 100% 25%,#153c4c55 0,transparent 30%),linear-gradient(140deg,#080d19 0%,#090f1c 52%,#0a1220 100%);background-attachment:fixed}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.15;background-image:linear-gradient(#7eb2ff0b 1px,transparent 1px),linear-gradient(90deg,#7eb2ff0b 1px,transparent 1px);background-size:44px 44px;mask-image:linear-gradient(to bottom,black,transparent 80%)}
main{max-width:1240px;padding-top:30px;position:relative;z-index:1}.top{margin-bottom:18px}.logo{width:48px;height:48px;border-radius:15px;background:linear-gradient(145deg,#1b3a62,#11223b);border-color:#4772a2;color:#9feaff;box-shadow:0 0 26px #2f8eff24,inset 0 1px #ffffff18}.brand h1{font-size:25px;letter-spacing:.015em}.brand p{color:#9eb2cf}.tag{background:#0e1a2b;border-color:#2d4666;color:#a8c0df;letter-spacing:.1em;font-weight:750}
.card{background:linear-gradient(150deg,#111c30f2,#0d1524f5);border-color:#263750;border-radius:18px;box-shadow:0 18px 48px #0003,inset 0 1px #ffffff08;backdrop-filter:blur(12px);padding:22px}.card h2{font-size:17px;letter-spacing:.015em}.global-card{overflow:hidden;position:relative;border-color:#31547c;background:linear-gradient(105deg,#142642f5,#101b2df5 62%,#0e1d2b);box-shadow:0 15px 45px #07142699,inset 0 1px #c0deff1c}.global-card:after{content:"";position:absolute;right:-75px;top:-130px;width:320px;height:320px;border-radius:50%;background:radial-gradient(circle,#3ba9ff22,transparent 68%);pointer-events:none}.global-card .toolbar,.global-card .actions{position:relative;z-index:1}.global-card .quality-pill{font-size:10px;padding:7px 12px}
.component-card{position:relative;overflow:hidden;background:linear-gradient(155deg,#111d30,#0c1422);border-color:#293b56;border-radius:15px;padding:17px;box-shadow:inset 0 1px #ffffff08;transition:transform .2s ease,border-color .2s ease,box-shadow .2s ease}.component-card:hover{transform:translateY(-2px);border-color:#4a6b91;box-shadow:0 12px 28px #0003,inset 0 1px #ffffff12}.component-card h3{display:flex;align-items:center;gap:9px;font-size:14px;letter-spacing:.025em}.component-card:nth-child(1) h3:before,.component-card:nth-child(2) h3:before,.component-card:nth-child(3) h3:before{display:grid;place-items:center;width:23px;height:23px;border:1px solid #36577c;border-radius:7px;background:#14263d;color:#8bdfff;font-size:10px;font-weight:850}.component-card:nth-child(1) h3:before{content:"01"}.component-card:nth-child(2) h3:before{content:"02"}.component-card:nth-child(3) h3:before{content:"03"}
.field label{color:#b5c7df;font-weight:600}.field input,.field select{background:#080f1c;border-color:#2b3d58;border-radius:10px;transition:border-color .18s,box-shadow .18s,background .18s}.field input:hover,.field select:hover{border-color:#405b7d}.field input:focus,.field select:focus{background:#0a1423;border-color:#67bdff;box-shadow:0 0 0 3px #63b4ff1c,0 0 18px #49a8ff12}.field input[type=password]{letter-spacing:.1em}
.btn{border-radius:10px;padding:10px 16px;background:linear-gradient(135deg,#51e4b1,#2bbd94);box-shadow:0 5px 16px #26bd8a22;transition:transform .16s,filter .16s,box-shadow .16s}.btn:hover{filter:brightness(1.09);transform:translateY(-1px);box-shadow:0 8px 20px #2bc99635}.btn:active{transform:translateY(0)}.btn.secondary{background:linear-gradient(135deg,#253956,#1b2a41);color:#dceaff;border-color:#405876;box-shadow:none}.btn.test{background:linear-gradient(135deg,#3975c1,#27528d);border-color:#548bd0;box-shadow:0 5px 18px #377dd222}.btn.stop{background:linear-gradient(135deg,#59283b,#3a1c2c);border-color:#7a4056;color:#ffdce5;box-shadow:none}.btn.stop:hover{box-shadow:0 7px 18px #ff476a1d}.btn:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}
.route-card{background:linear-gradient(110deg,#0a1422,#0b1726);border-color:#2b405e;border-radius:14px;padding:16px 18px}.route-card h3{display:flex;align-items:center;gap:8px;color:#c4d4ea;font-size:12px;letter-spacing:.08em;text-transform:uppercase}.route-card h3:before{content:"LIVE ROUTE";font-size:9px;letter-spacing:.12em;color:#82caff;border:1px solid #315477;background:#102239;padding:4px 7px;border-radius:99px}.route-line{gap:14px}.route-node{min-width:112px;text-align:center;border-radius:10px;padding:9px 14px;font-size:12px;letter-spacing:.015em;background:#291722}.route-node.ok{background:linear-gradient(135deg,#10342d,#0d2824);box-shadow:0 0 20px #27d49a13,inset 0 1px #ffffff0c}.route-node.wait{background:#2a2418}.route-arrow{color:#6484ac;text-shadow:0 0 12px #5ba7ff44}
.traffic-dials{gap:16px}.dial-card{position:relative;overflow:hidden;background:radial-gradient(ellipse at 50% 0,#152944,#0c1524 72%);border-color:#2a3e5b;border-radius:16px;padding:18px;box-shadow:inset 0 1px #ffffff0a}.dial-title{text-transform:uppercase;letter-spacing:.12em;font-size:11px;color:#b8cce7}.dial-svg{max-width:290px}.dial-track{stroke:#263b58;stroke-width:11}.dial-tick{fill:none;stroke:#7892b4;stroke-width:2;opacity:.85}.dial-needle{stroke:var(--blue);stroke-width:4.5}.dial-needle.receive{stroke:var(--green)}.dial-center{fill:#e9f5ff}.dial-speed{font-size:22px;letter-spacing:.015em;text-shadow:0 0 18px #6eb0ff2a}.dial-caption{color:#9baec8}.traffic-meta{display:flex;justify-content:center;flex-wrap:wrap;gap:9px 14px;border-top:1px solid #26364e;padding-top:14px}.traffic-meta .metric-line{text-align:left;min-width:155px}.traffic-meta .quality-pill{min-width:105px;justify-content:center}
.cert-picker{background:#09111e;border:1px dashed #3b5272;border-radius:12px;padding:13px}.cert-picker:focus-within{border-color:#71baff}.cert-picker input{accent-color:#60a9ff}.cert-status{padding-left:18px;padding-right:18px}.cert-status.missing{background:linear-gradient(135deg,#512236,#351826);border-color:#854257}.cert-status.uploaded{background:linear-gradient(135deg,#14503e,#10382d);border-color:#29926d;box-shadow:0 0 20px #24cd9630}.cert-info{line-height:1.6}.test-result{padding:9px 10px;border-radius:9px;background:#0b1421;border:1px solid #26374f}.test-result.ok{border-color:#226b55;background:#0c241e}.test-result.bad{border-color:#6b3042;background:#25131b}.logs{height:220px;background:#070c15;border-color:#283a54;border-radius:12px;color:#c2d3e9}.log-card .toolbar{margin-bottom:12px}.bottom-note{line-height:1.7;color:#8194b0}
.quality-pill{background:#101a29}.quality-pill.good{background:#102a25}.quality-pill.normal{background:#2a2418}.quality-pill.bad{background:#2a1720}.quality-pill.disconnected{background:#111a28}.dial-card.flash{border-color:#65a1ff;box-shadow:0 0 0 2px #65a1ff22,0 0 25px #4f8de722}.component-state{line-height:1.55}#appState.good{color:var(--green)}
.save-state{display:flex;align-items:center;gap:7px;margin-top:9px;padding:8px 10px;border:1px solid #2c405a;border-radius:9px;background:#0a1320;color:#9fb2ce;font-size:11px}.save-state:before{content:"";width:7px;height:7px;border-radius:50%;background:#8091aa}.save-state.saved{color:#aef4db;border-color:#23664f;background:#0b211c}.save-state.saved:before{background:var(--green);box-shadow:0 0 9px #39e0aa88}.save-state.saving{color:#bfdbff;border-color:#345987}.save-state.saving:before{background:var(--blue);box-shadow:0 0 9px #6eafff88}.save-state.error{color:#ffc3cf;border-color:#713648;background:#25141c}.save-state.error:before{background:var(--red)}
.ip-readout{position:relative;z-index:1;display:grid;grid-template-columns:1fr 1fr;gap:11px;margin-top:17px}.ip-panel{min-width:0;padding:14px 15px;border:1px solid #2b405e;border-radius:13px;background:linear-gradient(145deg,#0c1727dc,#0a1321)}.ip-panel.after{border-color:#315343;background:linear-gradient(145deg,#0e211edc,#0a1718)}.ip-heading{display:flex;align-items:center;gap:8px;color:#a9bdd8;font-size:10px;font-weight:800;letter-spacing:.12em;text-transform:uppercase}.ip-indicator{width:8px;height:8px;flex:0 0 auto;border-radius:50%;background:#71809a;box-shadow:0 0 0 4px #71809a1a}.ip-indicator.ready{background:var(--green);box-shadow:0 0 0 4px #39e0aa1a,0 0 12px #39e0aa77}.ip-indicator.error{background:var(--red);box-shadow:0 0 0 4px #ff55771a}.ip-value{margin-top:7px;color:#f0f5ff;font:700 clamp(16px,2.3vw,21px)/1.25 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;letter-spacing:.02em}.ip-note{margin-top:5px;color:#8295b1;font-size:11px;min-height:17px}.ip-footer{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:9px}.ip-source{color:#758aa8;font-size:10px}.ip-footer .btn{min-height:34px;padding:6px 11px;font-size:11px}
@media(max-width:900px){main{max-width:850px}.component-grid{grid-template-columns:1fr 1fr}.component-card:last-child{grid-column:1/-1}}
@media(max-width:620px){main{padding:18px 12px 32px}.card{padding:16px}.brand h1{font-size:21px}.brand p{font-size:11px}.global-card .toolbar{align-items:flex-start}.global-card .actions .btn{flex:1}.component-grid,.traffic-dials{grid-template-columns:1fr}.component-card:last-child{grid-column:auto}.component-card .profile-actions{grid-template-columns:1fr 1fr}.component-card .profile-actions select{grid-column:1/-1}.cert-row{grid-template-columns:1fr}.route-node{min-width:0}.traffic-meta{justify-content:flex-start}.traffic-meta .metric-line{min-width:calc(100% - 125px)}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style>
<style>@media(max-width:620px){.ip-readout{grid-template-columns:1fr}.ip-footer{align-items:flex-start;flex-direction:column}.ip-footer .btn{width:100%}}</style>
<style>
.connection-health{display:flex;align-items:center;justify-content:center;gap:10px;flex-wrap:wrap;border-top:1px solid #26364e;margin-top:14px;padding-top:14px}.health-factors{font-size:12px;color:#b2c1d6;text-align:center}.traffic-note{font-size:11px;color:var(--muted)}
@media(max-width:620px){.connection-health{justify-content:flex-start}.health-factors{text-align:left}}
</style>
</head>
<body>
<main>
  <header class="top"><div class="brand"><div class="logo">M</div><div><h1>MedoVPN</h1><p>Browser → MedoVPN → V2RayNG → Google Apps Script</p></div></div><div class="tag">MEDOVPN · CROSS-PLATFORM GO</div></header>
  <section class="card global-card">
    <div class="toolbar"><div><h2>Whole VPN connection</h2><p class="section-note">Start or stop the complete local proxy route.</p></div><span id="appState" class="quality-pill disconnected">Disconnected</span></div>
    <div class="actions"><button class="btn" id="connectBtn">Connect whole VPN</button><button class="btn stop" id="stopBtn">Disconnect whole VPN</button><button class="btn secondary" id="quitBtn">Exit app</button></div>
    <div class="test-result bad" id="configBanner" hidden style="margin-top:12px">Settings differ from the running proxy. Disconnect and Connect to apply.</div><div class="ip-readout" aria-label="Public IP before and after VPN">
      <div class="ip-panel"><div class="ip-heading"><span class="ip-indicator" id="ipBeforeDot"></span>Before · direct IP</div><div class="ip-value" id="ipBefore" aria-live="polite">Waiting for lookup</div><div class="ip-note" id="ipBeforeNote">Direct internet connection</div></div>
      <div class="ip-panel after"><div class="ip-heading"><span class="ip-indicator" id="ipAfterDot"></span>After · V2RayNG exit IP</div><div class="ip-value" id="ipAfter" aria-live="polite">Not captured</div><div class="ip-note" id="ipAfterNote">Connect the app to read the VPN route</div></div>
    </div>
    <div class="ip-footer"><span class="ip-source">Public IP from ipify, AWS checkip or icanhazip · exit IP is measured through V2RayNG, not through GAS or the Worker</span><button class="btn secondary" id="refreshIPBtn" type="button">Refresh IP</button></div>
  </section>
  <div class="grid">
    <section class="card wide" id="proxyConnectionsCard">
      <h2>Proxy connections</h2>
      <div class="component-grid">
        <section class="component-card">
          <h3>Browser</h3>
          <div class="form-grid"><div class="field"><label for="browserIP">Browser proxy IP</label><input id="browserIP" autocomplete="off" value="127.0.0.1"></div><div class="field"><label for="browserPort">Port</label><input id="browserPort" type="number" min="1" max="65535" value="5555"></div></div>
          <div class="component-actions"><button class="btn" id="browserConnectBtn">Connect</button><button class="btn stop" id="browserStopBtn">Disconnect</button></div>
          <div class="component-state" id="browserStatus">Proxy stopped</div>
        </section>
        <section class="component-card">
          <h3>V2RayNG</h3>
          <div class="field"><label>V2RayNG local proxy</label><div class="v2ray-row"><input id="v2rayIP" aria-label="V2RayNG IP" autocomplete="off" value="127.0.0.1"><input id="v2rayPort" aria-label="V2RayNG port" type="number" min="1" max="65535" value="10808"><select id="v2rayType" class="type" aria-label="V2RayNG proxy type"><option value="http">HTTP proxy</option><option value="socks5">SOCKS5 proxy</option></select></div><div class="hint">Default port: 10808. Choose the inbound type configured in V2RayNG.</div></div>
          <div class="component-actions"><button class="btn" id="v2rayConnectBtn">Connect</button><button class="btn stop" id="v2rayStopBtn">Disconnect</button></div>
          <div class="component-state" id="v2rayStatus">Not checked</div>
        </section>
        <section class="component-card">
          <h3>Google Apps Script</h3>
          <div class="field"><label for="gasURL">Google Apps Script web app URL</label><input id="gasURL" type="url" spellcheck="false" autocomplete="off"></div>
          <div class="field" style="margin-top:10px"><label for="authKey">GAS AUTH_KEY</label><div class="secret-row"><input id="authKey" type="password" autocomplete="new-password" placeholder="Enter your GAS AUTH_KEY"><button class="btn secondary" id="toggleAuthKey" type="button" aria-pressed="false">Show</button></div></div>
          <div class="component-actions"><button class="btn test" id="testBtn">Test GAS</button></div>
          <div class="component-actions"><button class="btn" id="gasConnectBtn">Connect</button><button class="btn stop" id="gasStopBtn">Disconnect</button></div>
          <div class="component-state" id="gasStatus">Run Test GAS</div>
          <div class="field" style="margin-top:10px"><label for="profileSelect">Saved GAS profiles</label><div class="profile-actions"><select id="profileSelect" aria-label="Choose a saved GAS profile"></select><button class="btn secondary" id="saveProfileBtn" type="button">Save profile</button><button class="btn stop" id="deleteProfileBtn" type="button">Delete</button></div></div>
          <div class="field" style="margin-top:10px"><label for="profileName">Profile name (optional)</label><input id="profileName" autocomplete="off" placeholder="Leave blank for an automatic name"></div>
          <div id="saveStatus" class="save-state">GAS credentials and proxy addresses save locally.</div>
          <div class="test-result" id="testResult">Test GAS checks V2RayNG reachability and AUTH_KEY. It does not start the whole VPN.</div>
        </section>
      </div>
      <section class="route-card" aria-label="Connection status"><h3>Connection path</h3><div class="route-line"><span class="route-node" id="routeBrowser">Browser</span><span class="route-arrow">➜</span><span class="route-node ok" id="routeVPN">MedoVPN</span><span class="route-arrow">➜</span><span class="route-node" id="routeV2ray">V2RayNG</span></div></section>
    </section>
    <section class="card wide">
      <h2>Upload HTTPS interception CA</h2>
      <div class="cert-row"><div class="cert-picker"><label for="caCert">Browse for CA certificate (.crt, .cer, or .pem)</label><input id="caCert" type="file" accept=".crt,.cer,.pem,.der"></div><div class="cert-picker"><label for="caKey">Browse for its matching private key (.key or .pem)</label><input id="caKey" type="file" accept=".key,.pem,.der"></div></div>
      <div class="actions"><button class="btn cert-status missing" id="uploadBtn">Upload CA pair to Go · Not uploaded</button><a class="btn secondary btnlink" href="/api/ca-cert" download>Download CA certificate</a><button class="btn stop" id="regenCaBtn" type="button">Regenerate CA…</button><span id="caUploadState" class="hint">No CA pair uploaded.</span></div>
      <div class="hint cert-info">Go needs both matching files to sign per-site HTTPS certificates. Stop the proxy before uploading. The private key stays in the local Go app folder and is never written to logs.</div>
    </section>
    <section class="card wide" id="trafficCard">
      <div class="toolbar"><h2>Sent and received data</h2><span class="traffic-note">Payload bytes · 5-second average</span></div>
      <div class="traffic-dials">
        <div class="dial-card" id="sentCard"><div class="dial-title">Sent</div><svg class="dial-svg" viewBox="0 0 240 145" role="img" aria-label="Sent traffic speed gauge"><path class="dial-track" d="M 22 122 A 98 98 0 0 1 218 122" /><path class="dial-tick" d="M 28 112 l 12 4 M 52 55 l 9 9 M 120 24 v 14 M 188 55 l -9 9 M 212 112 l -12 4" /><line class="dial-needle" id="sentNeedle" x1="120" y1="122" x2="120" y2="36" transform="rotate(-90 120 122)" /><circle class="dial-center" cx="120" cy="122" r="7" /></svg><div class="dial-speed" id="sentSpeed">0 B/s</div><div class="dial-caption"><span id="sentSize">0 B</span> total · <span id="sentCount">0</span> requests</div></div>
        <div class="dial-card" id="receivedCard"><div class="dial-title">Receive</div><svg class="dial-svg" viewBox="0 0 240 145" role="img" aria-label="Received traffic speed gauge"><path class="dial-track" d="M 22 122 A 98 98 0 0 1 218 122" /><path class="dial-tick" d="M 28 112 l 12 4 M 52 55 l 9 9 M 120 24 v 14 M 188 55 l -9 9 M 212 112 l -12 4" /><line class="dial-needle receive" id="receivedNeedle" x1="120" y1="122" x2="120" y2="36" transform="rotate(-90 120 122)" /><circle class="dial-center" cx="120" cy="122" r="7" /></svg><div class="dial-speed" id="receivedSpeed">0 B/s</div><div class="dial-caption"><span id="receivedSize">0 B</span> total · <span id="receivedCount">0</span> responses</div></div>
      </div>
      <div class="connection-health" aria-label="Connection health factors"><span id="routeQuality" class="quality-pill disconnected">Awaiting traffic</span><span id="routeHealthFactors" class="health-factors">V2RayNG reachability · recent relay success · latency · jitter</span></div>
    </section>
  </div>
  <section class="card log-card"><div class="toolbar"><h2>Results and logs</h2><span class="small" id="logCount">0 entries</span></div><pre class="logs" id="logs"><span class="empty">Logs will appear here.</span></pre></section>
  <p class="bottom-note">Configure Firefox HTTP and HTTPS proxy to the Browser proxy IP and port above. Import the active CA certificate into Firefox to open HTTPS sites through the local MITM proxy.</p>
</main>
<script id="boot" type="application/json">__BOOT_DATA__</script>
<script>
const boot=JSON.parse(document.getElementById('boot').textContent);const $=id=>document.getElementById(id);const BUILT_IN_PROFILE='builtin-default';const inputIds=['browserIP','browserPort','v2rayIP','v2rayPort','v2rayType','gasURL','authKey'];let previous={sentBytes:null,receivedBytes:null,sampleAt:null,sentRate:0,receivedRate:0,browser:null},lastStatusError='',savedProfiles=boot.profiles||[],settingsSaveTimer=0,runningState=null,afterIPCaptured=false,nextAfterIPAttempt=0,afterIPFailures=0,ipControllers={before:null,after:null},lastPublicIPs={before:'',after:''};
let loadedProfileID=boot.activeProfileID;let saveChain=Promise.resolve();function enqueue(fn){const run=saveChain.then(fn,fn);saveChain=run.catch(()=>{});return run}
const initial=boot.settings||{};for(const key of inputIds){if(initial[key]!==undefined&&initial[key]!==null)$(key).value=initial[key]}
function settings(){return{browserIP:$('browserIP').value.trim(),browserPort:Number($('browserPort').value),v2rayIP:$('v2rayIP').value.trim(),v2rayPort:Number($('v2rayPort').value),v2rayType:$('v2rayType').value,gasURL:$('gasURL').value.trim(),authKey:$('authKey').value}}
function updateProfileControls(){$('deleteProfileBtn').disabled=!$('profileSelect').value||$('profileSelect').value===BUILT_IN_PROFILE}
function renderProfiles(profiles,activeID){savedProfiles=Array.isArray(profiles)?profiles:[];const select=$('profileSelect');select.replaceChildren();for(const profile of savedProfiles){const option=document.createElement('option');option.value=profile.id;option.textContent=(profile.id===BUILT_IN_PROFILE?'Built-in default':profile.name)+' — '+profile.gasURL+(profile.authKey?'':' (key missing)');select.appendChild(option)}if(activeID)select.value=activeID;if(select.selectedIndex<0&&select.options.length)select.selectedIndex=0;updateProfileControls()}
function applyProfile(profile){if(!profile)return;loadedProfileID=profile.id;$('gasURL').value=profile.gasURL||'';$('authKey').value=profile.authKey||'';$('profileName').value=profile.id===BUILT_IN_PROFILE?'':(profile.name||'');$('profileSelect').value=profile.id;updateProfileControls();scheduleConfigCheck()}
renderProfiles(savedProfiles,boot.activeProfileID);const startingProfile=savedProfiles.find(profile=>profile.id===boot.activeProfileID);if(startingProfile&&startingProfile.id!==BUILT_IN_PROFILE)$('profileName').value=startingProfile.name||'';
setSaveStatus('saved','Loaded from the local settings file.');
function bytes(n){n=Number(n||0);if(n<1024)return n+' B';if(n<1048576)return(n/1024).toFixed(1)+' KB';if(n<1073741824)return(n/1048576).toFixed(2)+' MB';return(n/1073741824).toFixed(2)+' GB'}
function rate(n){n=Number(n||0);if(!Number.isFinite(n)||n<=0)return'0 B/s';if(n<1024)return n.toFixed(0)+' B/s';if(n<1048576)return(n/1024).toFixed(1)+' KB/s';if(n<1073741824)return(n/1048576).toFixed(2)+' MB/s';return(n/1073741824).toFixed(2)+' GB/s'}
function setNeedle(id,value){const maximum=10*1024*1024;const amount=Math.max(0,Number(value)||0);const ratio=Math.min(1,Math.log1p(amount)/Math.log1p(maximum));const degrees=-90+180*ratio;$(id).setAttribute('transform','rotate('+degrees.toFixed(1)+' 120 122)')}
function setNode(id,state){const el=$(id);el.className='route-node'+(state?' '+state:'')}
function setQuality(id,value){const q=String(value||'DISCONNECTED').toUpperCase();const names={GOOD:['good','Good'],NORMAL:['normal','Normal'],BAD:['bad','Bad'],IDLE:['disconnected','Awaiting traffic'],DISCONNECTED:['disconnected','Disconnected']};const pair=names[q]||names.DISCONNECTED;const el=$(id);el.className='quality-pill '+pair[0];el.textContent=pair[1]}
function latencyText(s){const first=s.latencyReady?Number(s.latencyMs).toFixed(0)+' ms':'—';const full=s.latencyReady?Number(s.fullLatencyMs).toFixed(0)+' ms':'—';const jitter=s.jitterReady?Number(s.jitterMs).toFixed(0)+' ms':s.latencyReady?'need 2 samples':'—';return'GAS first byte '+first+', full '+full+' · jitter '+jitter}
function healthFactors(s){const parts=[];parts.push(s.browserConnected?'browser proxy active':'browser traffic not detected');parts.push(s.v2rayKnown?(s.v2rayConnected?'V2RayNG local port reachable':'V2RayNG local port unreachable'):'V2RayNG not checked');if(Number(s.metricSampleCount)>0){parts.push('recent relay success '+Number(s.metricSuccessRate||0).toFixed(0)+'% ('+s.metricSampleCount+' checks)');if(Number(s.metricFailureCount)>0)parts.push(s.metricFailureCount+' recent failure'+(s.metricFailureCount===1?'':'s'))}else parts.push('waiting for relay traffic');if(s.latencyReady)parts.push('GAS first byte '+Number(s.latencyMs).toFixed(0)+' ms, full '+Number(s.fullLatencyMs).toFixed(0)+' ms');if(s.gasRetries>0)parts.push(s.gasRetries+' retr'+(s.gasRetries===1?'y':'ies'));if(s.running&&s.certRejects>0)parts.push('Browser rejected '+s.certRejects+' HTTPS certificate'+(s.certRejects===1?'':'s')+'; import the CA');if(s.jitterReady)parts.push('jitter '+Number(s.jitterMs).toFixed(0)+' ms');if(s.metricFailureCount>0&&s.metricError)parts.push('last error: '+String(s.metricError).slice(0,120));return parts.join(' · ')}
function setIPStatus(route,message,state){$(route==='after'?'ipAfterNote':'ipBeforeNote').textContent=message;$(route==='after'?'ipAfterDot':'ipBeforeDot').className='ip-indicator'+(state?' '+state:'');if(state==='error')$(route==='after'?'ipAfter':'ipBefore').textContent='Unavailable';else if(!lastPublicIPs[route])$(route==='after'?'ipAfter':'ipBefore').textContent=message.startsWith('Waiting')?'Waiting':'Checking…'}
const BEFORE_KEY='medovpn-before-ip';let beforeStamp='';
function loadRealIP(){try{return JSON.parse(localStorage.getItem(BEFORE_KEY)||'null')}catch{return null}}
function saveRealIP(ip){try{localStorage.setItem(BEFORE_KEY,JSON.stringify({ip:ip,at:Date.now()}))}catch{}}
function forgetRealIP(){try{localStorage.removeItem(BEFORE_KEY)}catch{}}
function reconcileIPs(){const b=lastPublicIPs.before,a=lastPublicIPs.after;if(!b)return;const note=$('ipBeforeNote'),dot=$('ipBeforeDot');if(a&&b.includes(':')!==a.includes(':')){note.textContent='Cannot compare IPv4 with IPv6.';dot.className='ip-indicator ready';return}if(a&&b===a){const saved=loadRealIP();if(saved&&saved.ip===b)forgetRealIP();const hint=saved&&saved.ip&&saved.ip!==b?' Last real IP seen here: '+saved.ip+' ('+new Date(saved.at).toLocaleString()+').':'';note.textContent='Both routes report the same public IP. The V2RayNG route has not produced a different exit IP.'+hint;dot.className='ip-indicator error'}else{note.textContent='Direct public IP captured '+beforeStamp;dot.className='ip-indicator ready'}}
function resetAfterIP(){if(ipControllers.after){ipControllers.after.abort();ipControllers.after=null}lastPublicIPs.after='';$('ipAfter').textContent='Not captured';$('ipAfterNote').textContent='Connect the app to read the V2RayNG route';$('ipAfterDot').className='ip-indicator';reconcileIPs()}
async function readPublicIP(vpnActive){const route=vpnActive?'after':'before',controller=new AbortController();if(ipControllers[route])ipControllers[route].abort();ipControllers[route]=controller;lastPublicIPs[route]='';const timeout=setTimeout(()=>controller.abort(),10000);setIPStatus(route,vpnActive?'Checking through the configured V2RayNG route…':'Checking the direct internet route…','');try{const result=await api('/api/public-ip',{route:vpnActive?'vpn':'direct',v2rayIP:$('v2rayIP').value.trim(),v2rayPort:Number($('v2rayPort').value),v2rayType:$('v2rayType').value},controller.signal),ip=String(result.ip||'').trim();if(!/^[0-9a-fA-F:.]{3,45}$/.test(ip))throw new Error('The local app returned an invalid IP address');if(ipControllers[route]!==controller)return;lastPublicIPs[route]=ip;$(route==='after'?'ipAfter':'ipBefore').textContent=ip;const stamp=new Date().toLocaleTimeString();if(route==='before'){beforeStamp=stamp;if(!lastPublicIPs.after)saveRealIP(ip)}setIPStatus(route,'Public IP captured '+stamp,'ready');reconcileIPs();if(vpnActive&&runningState===true){afterIPCaptured=true;nextAfterIPAttempt=0;afterIPFailures=0}}catch(e){if(ipControllers[route]!==controller)return;if(vpnActive&&runningState===true){afterIPCaptured=false;nextAfterIPAttempt=Date.now()+Math.min(60000,4000*2**afterIPFailures);afterIPFailures++}setIPStatus(route,(vpnActive?'VPN IP lookup failed: ':'Direct IP lookup failed: ')+e.message,'error')}finally{clearTimeout(timeout);if(ipControllers[route]===controller)ipControllers[route]=null}}
async function refreshCurrentPublicIP(){afterIPFailures=0;nextAfterIPAttempt=0;if(runningState===null)await refresh();readPublicIP(false);if(runningState===true)readPublicIP(true)}
async function api(path,body,signal){const options=body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)};if(signal)options.signal=signal;const response=await fetch(path,options);let data={};try{data=await response.json()}catch{}if(!response.ok)throw new Error(data.message||'HTTP '+response.status);return data}
function logUIError(message){api('/api/ui-log',{message:String(message)}).catch(()=>{})}
async function refresh(){try{const s=await api('/api/status');const isRunning=!!s.running;if(runningState===null){runningState=isRunning;readPublicIP(false)}else if(runningState!==isRunning){runningState=isRunning;afterIPCaptured=false;nextAfterIPAttempt=0;afterIPFailures=0;if(!isRunning){$('configBanner').hidden=true;resetAfterIP();readPublicIP(false)}else scheduleConfigCheck()}if(isRunning&&!afterIPCaptured&&Date.now()>=nextAfterIPAttempt&&!(s.v2rayKnown&&!s.v2rayConnected)){afterIPCaptured=true;readPublicIP(true)}const address=s.browserAddress||$('browserIP').value+':'+$('browserPort').value;const certNote=s.running&&s.certRejects>0?' · Browser rejected '+s.certRejects+' HTTPS certificate'+(s.certRejects===1?'':'s')+'; import the CA':'';$('browserStatus').textContent=(s.running?(s.browserConnected?'Browser reached '+address:'Listening at '+address+' · waiting for browser'):'Go proxy is stopped')+certNote;const showTest=!s.running&&s.testKnown;$('v2rayStatus').textContent=showTest&&s.testV2RayChecked?'Last test: '+(s.testV2RayConnected?'V2RayNG local port reachable.':'V2RayNG local port not reachable.'):(s.v2rayKnown?s.v2rayMessage:'Not checked; press Connect or Test GAS');$('gasStatus').textContent=showTest?'Last test: '+s.testMessage:(s.gasKnown?s.gasMessage+' · '+latencyText(s)+' · '+String(s.connectionQuality||'DISCONNECTED').toLowerCase():'Run Test GAS');
setNode('routeBrowser',s.browserConnected?'ok':'');setNode('routeVPN',s.running?'ok':'');setNode('routeV2ray',!s.v2rayKnown?'wait':s.running&&s.v2rayConnected?'ok':'');const appState=$('appState');if(s.state==='starting'||s.state==='stopping'){appState.textContent=s.state==='starting'?'Starting…':'Stopping…';appState.className='quality-pill normal'}else{appState.textContent=!s.running?'Disconnected':s.v2rayConnected?'Connected':'Waiting for V2RayNG';appState.className='quality-pill '+(!s.running?'disconnected':s.v2rayConnected?'good':'bad')}
const sentBytes=Number(s.sentBytes)||0,receivedBytes=Number(s.receivedBytes)||0,now=performance.now();if(previous.sampleAt===null){previous.sampleAt=now;previous.sentBytes=sentBytes;previous.receivedBytes=receivedBytes}else if(now-previous.sampleAt>=5000){const seconds=(now-previous.sampleAt)/1000;previous.sentRate=seconds>0&&sentBytes>=previous.sentBytes?(sentBytes-previous.sentBytes)/seconds:0;previous.receivedRate=seconds>0&&receivedBytes>=previous.receivedBytes?(receivedBytes-previous.receivedBytes)/seconds:0;previous.sampleAt=now;previous.sentBytes=sentBytes;previous.receivedBytes=receivedBytes;$('sentSpeed').textContent=rate(previous.sentRate);setNeedle('sentNeedle',previous.sentRate);$('receivedSpeed').textContent=rate(previous.receivedRate);setNeedle('receivedNeedle',previous.receivedRate)}
$('sentCount').textContent=s.sentRequests;$('sentSize').textContent=bytes(sentBytes);$('receivedCount').textContent=s.receivedResponses;$('receivedSize').textContent=bytes(receivedBytes);setQuality('routeQuality',s.running?s.connectionQuality:'DISCONNECTED');$('routeHealthFactors').textContent=healthFactors(s);
const stateName=s.state||(s.running?'running':'stopped');for(const id of ['connectBtn','browserConnectBtn','v2rayConnectBtn','gasConnectBtn'])$(id).disabled=stateName!=='stopped';for(const id of ['stopBtn','browserStopBtn','v2rayStopBtn','gasStopBtn'])$(id).disabled=!(stateName==='starting'||stateName==='running');
caUploadedNow=!!s.caUploaded;if(Date.now()>=caHoldUntil){const caParts=[caUploadedNow?'Uploaded CA pair is saved and used on start.':'No CA pair uploaded; the default CA is used.'];if(s.caFingerprint)caParts.push('Active CA SHA-256 '+String(s.caFingerprint).slice(0,16)+'…');if(s.caExpires){const expires=new Date(s.caExpires),days=Math.floor((expires-Date.now())/864e5);caParts.push(days<0?'EXPIRED '+expires.toLocaleDateString():days<=30?'expires in '+days+' day'+(days===1?'':'s'):'expires '+expires.toLocaleDateString())}if(s.caWarning)caParts.push('Warning: '+s.caWarning);setCAState(caUploadedNow,caParts.join(' · '))}$('regenCaBtn').disabled=stateName!=='stopped'||caUploadedNow;
lastStatusError='';}catch(e){const message='GUI status error: '+e.message;$('browserStatus').textContent=message;setNode('routeBrowser','');setNode('routeVPN','');setNode('routeV2ray','');if(lastStatusError!==message){lastStatusError=message;logUIError(message)}}}
let lastLogText='';
async function refreshLogs(){try{const data=await api('/api/logs');const lines=data.lines||[];$('logCount').textContent=lines.length+' entries';const text=lines.length?lines.join('\n'):'Logs will appear here.';if(text===lastLogText)return;const el=$('logs'),selection=window.getSelection();if(selection&&!selection.isCollapsed&&el.contains(selection.anchorNode))return;const stick=el.scrollTop+el.clientHeight>=el.scrollHeight-24;el.textContent=text;lastLogText=text;if(stick)el.scrollTop=el.scrollHeight}catch{}}
function setTest(text,ok){const el=$('testResult');el.textContent=text;el.className='test-result '+(ok===true?'ok':ok===false?'bad':'');if(ok===false)logUIError(text)}
let configTimer=0;
function scheduleConfigCheck(){if(configTimer)clearTimeout(configTimer);configTimer=setTimeout(()=>{configTimer=0;checkConfigMatch()},400)}
async function checkConfigMatch(){const banner=$('configBanner');if(runningState!==true){banner.hidden=true;return}try{const r=await api('/api/config-match',settings());banner.hidden=!r.running||!!r.match}catch{}}
function setSaveStatus(state,message){const el=$('saveStatus');el.className='save-state '+state;el.textContent=message}
function saveCurrentProfile(quiet,forceNew){return enqueue(async()=>{const config=settings();if(!config.gasURL||!config.authKey.trim()){if(!quiet)setTest('Enter a GAS URL and AUTH_KEY before saving a profile.',false);setSaveStatus('error','Enter a GAS URL and AUTH_KEY to save locally.');return false}const selected=savedProfiles.find(profile=>profile.id===loadedProfileID);const unchanged=selected&&selected.gasURL===config.gasURL&&selected.authKey===config.authKey;const name=$('profileName').value.trim();if(!forceNew&&unchanged&&selected.id===BUILT_IN_PROFILE&&!name){setSaveStatus('saved','Connection settings are saved locally.');return true}const id=!forceNew&&selected&&selected.id!==BUILT_IN_PROFILE?selected.id:'';try{const result=await api('/api/profiles/save',{id,name,settings:config});renderProfiles(result.profiles,result.activeProfileID);loadedProfileID=result.activeProfileID;$('profileName').value=result.profile.name||'';setSaveStatus('saved','GAS credentials and proxy addresses saved locally.');if(!quiet)setTest(result.message,true);return true}catch(e){setSaveStatus('error','Could not save settings: '+e.message);if(quiet)logUIError(e.message);else setTest(e.message,false);return false}})}
function persistAllSettings(){return enqueue(async()=>{const config=settings();if(!config.gasURL||!config.authKey.trim())return true;const selected=savedProfiles.find(profile=>profile.id===loadedProfileID);if(selected&&selected.id===BUILT_IN_PROFILE&&selected.gasURL===config.gasURL&&selected.authKey===config.authKey)return true;const editingExisting=selected&&selected.id!==BUILT_IN_PROFILE;const id=editingExisting?selected.id:'';const name=$('profileName').value.trim()||(editingExisting?selected.name:'Saved connection settings');setSaveStatus('saving','Saving GAS credentials and proxy addresses…');try{const result=await api('/api/profiles/save',{id,name,settings:config});renderProfiles(result.profiles,result.activeProfileID);loadedProfileID=result.activeProfileID;$('profileName').value=result.profile.name||name;setSaveStatus('saved','GAS credentials and proxy addresses saved locally.');return true}catch(e){setSaveStatus('error','Could not save settings: '+e.message);logUIError(e.message);return false}})}
function saveNetworkSettings(){return enqueue(async()=>{const c=settings();try{await api('/api/settings/save',{browserIP:c.browserIP,browserPort:c.browserPort,v2rayIP:c.v2rayIP,v2rayPort:c.v2rayPort,v2rayType:c.v2rayType});setSaveStatus('saved','Proxy addresses saved locally.');return true}catch(e){setSaveStatus('error','Could not save proxy addresses: '+e.message);return false}})}
function scheduleSettingsSave(){if(settingsSaveTimer)clearTimeout(settingsSaveTimer);setSaveStatus('saving','Saving changes to local settings…');settingsSaveTimer=setTimeout(()=>{settingsSaveTimer=0;persistAllSettings()},750)}
const networkIds=['browserIP','browserPort','v2rayIP','v2rayPort','v2rayType'];for(const id of inputIds){$(id).addEventListener('change',networkIds.includes(id)?()=>{saveNetworkSettings();scheduleConfigCheck()}:()=>{scheduleSettingsSave();scheduleConfigCheck()});$(id).addEventListener('input',scheduleConfigCheck)}
$('profileName').addEventListener('change',()=>saveCurrentProfile(true,false));
$('profileSelect').onchange=async()=>{const sel=$('profileSelect'),requestedID=sel.value,previousID=loadedProfileID;sel.disabled=true;try{if(settingsSaveTimer){clearTimeout(settingsSaveTimer);settingsSaveTimer=0}await persistAllSettings();const r=await api('/api/profiles/select',{id:requestedID});renderProfiles(r.profiles,r.activeProfileID);applyProfile(r.profile);setSaveStatus('saved','Selected profile loaded from local settings.')}catch(e){sel.value=previousID;setTest(e.message,false)}finally{sel.disabled=false}};
$('saveProfileBtn').onclick=()=>saveCurrentProfile(false,false);
$('deleteProfileBtn').onclick=async()=>{const id=$('profileSelect').value;if(!id||id===BUILT_IN_PROFILE)return;if(!confirm('Delete this saved GAS profile?'))return;try{const result=await api('/api/profiles/delete',{id});renderProfiles(result.profiles,result.activeProfileID);applyProfile(result.profile);setTest(result.message,true)}catch(e){setTest(e.message,false)}};
$('toggleAuthKey').onclick=()=>{const input=$('authKey'),button=$('toggleAuthKey'),showing=input.type==='password';input.type=showing?'text':'password';button.textContent=showing?'Hide':'Show';button.setAttribute('aria-pressed',String(showing))};
async function startProxy(){for(const id of ['connectBtn','browserConnectBtn','v2rayConnectBtn','gasConnectBtn'])$(id).disabled=true;setTest('Starting MedoVPN proxy…');try{const saved=await saveCurrentProfile(true,false);const r=await api('/api/start',settings());if(!r.ok)throw new Error(r.message||'Could not start Go proxy');const persisted=saved&&r.persisted!==false;setSaveStatus(persisted?'saved':'error',persisted?'GAS credentials and proxy addresses saved locally.':'Proxy started, but settings could NOT be saved. Press Save profile to retry.');setTest(r.message,true)}catch(e){setTest(e.message,false)}finally{await refresh();scheduleConfigCheck()}}
async function stopProxy(){for(const id of ['stopBtn','browserStopBtn','v2rayStopBtn','gasStopBtn'])$(id).disabled=true;try{const r=await api('/api/stop',{});setTest(r.message,true)}catch(e){setTest(e.message,false)}await refresh()}
for(const id of ['connectBtn','browserConnectBtn','v2rayConnectBtn','gasConnectBtn'])$(id).onclick=startProxy;
for(const id of ['stopBtn','browserStopBtn','v2rayStopBtn','gasStopBtn'])$(id).onclick=stopProxy;
$('quitBtn').onclick=async()=>{try{if(settingsSaveTimer){clearTimeout(settingsSaveTimer);settingsSaveTimer=0;await persistAllSettings()}const r=await api('/api/quit',{});setTest(r.message,true)}catch(e){setTest(e.message,false)}};
$('testBtn').onclick=async()=>{const b=$('testBtn');b.disabled=true;setTest('Testing GAS reachability… This does not start or change the whole VPN connection.');try{await saveCurrentProfile(true,false);const r=await api('/api/test',settings());setTest(r.message,r.ok);await refresh()}catch(e){setTest(e.message,false)}finally{b.disabled=false;await refresh()}};
function setCAState(uploaded,message){const button=$('uploadBtn');button.className='btn cert-status '+(uploaded?'uploaded':'missing');button.textContent=uploaded?'CA pair uploaded ✓':'Upload CA pair to Go · Not uploaded';$('caUploadState').textContent=message}
let caUploadedNow=false,caHoldUntil=0;
$('uploadBtn').onclick=async()=>{const cert=$('caCert').files[0],key=$('caKey').files[0];caHoldUntil=Date.now()+8000;if(!cert||!key){setCAState(caUploadedNow,'Select both files to upload a CA pair.');setTest('Browse and select both the CA certificate and its matching private key.',false);return}const form=new FormData();form.append('caCert',cert);form.append('caKey',key);$('uploadBtn').disabled=true;try{const response=await fetch('/api/upload-ca',{method:'POST',body:form});const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.message||'Upload failed');caUploadedNow=true;setCAState(true,'Certificate and matching key uploaded and saved.');setTest(result.message,true)}catch(e){setCAState(caUploadedNow,e.message);setTest(e.message,false)}finally{$('uploadBtn').disabled=false;await refreshLogs();await refresh()}};
$('regenCaBtn').onclick=async()=>{if(!confirm('Generate a new HTTPS interception CA? The current one is moved to a ca-old folder and you must import the new certificate into your browser again.'))return;caHoldUntil=Date.now()+8000;try{const r=await api('/api/ca/regenerate',{});setTest(r.message,!!r.ok);setCAState(caUploadedNow,r.message)}catch(e){setTest(e.message,false)}await refreshLogs();await refresh()};
$('refreshIPBtn').onclick=refreshCurrentPublicIP;
async function reportBrowser(state){if(previous.browser===state)return;previous.browser=state;try{await api('/api/browser-log',{state})}catch{}}
function checkBrowser(){const image=new Image();image.onload=()=>{reportBrowser('connected')};image.onerror=()=>{reportBrowser('disconnected')};image.src='http://gas-proxy-check.invalid/'+encodeURIComponent(boot.probeToken)+'?t='+Date.now()}
refresh();refreshLogs();setInterval(refresh,1200);setInterval(refreshLogs,1800);setInterval(checkBrowser,2500);checkBrowser();
</script>
</body></html>`

func (p *proxyApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.isBrowserProbe(r) {
		p.lastBrowserSeen.Store(time.Now().UnixMilli())
		w.Header().Set("Content-Type", "image/gif")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"))
		return
	}
	if p.isDashboardRequest(r) && p.dashboardHandler != nil {
		p.dashboardHandler.ServeHTTP(w, r)
		return
	}
	p.lastBrowserSeen.Store(time.Now().UnixMilli())
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	target := r.URL.String()
	if !r.URL.IsAbs() || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
		http.Error(w, "proxy expects an absolute http:// or https:// URL", http.StatusBadRequest)
		return
	}
	response, err := p.relay(r, target)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Printf("relay %s %s: %v", r.Method, target, err)
		}
		status, message := relayFailure(err)
		http.Error(w, message, status)
		return
	}
	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
	response.Body.Close()
}

func (p *proxyApp) isBrowserProbe(r *http.Request) bool {
	if r.Method != http.MethodGet || p.browserProbeToken == "" {
		return false
	}
	host := ""
	if r.URL.IsAbs() {
		host = r.URL.Hostname()
	} else {
		host = r.Host
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	}
	return strings.EqualFold(host, "gas-proxy-check.invalid") && r.URL.Path == "/"+p.browserProbeToken
}

func (p *proxyApp) isDashboardRequest(r *http.Request) bool {
	if r.Method == http.MethodConnect || !r.URL.IsAbs() || r.URL.Scheme != "http" {
		return false
	}
	host := strings.ToLower(r.URL.Hostname())
	if host != "localhost" && net.ParseIP(host) == nil {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
		return false
	}
	port := r.URL.Port()
	if port == "" {
		port = "80"
	}
	wantPort := strconv.Itoa(p.dashboardPort)
	return p.dashboardPort > 0 && port == wantPort
}

func (p *proxyApp) trackConnection(conn net.Conn) bool {
	p.activeMu.Lock()
	defer p.activeMu.Unlock()
	if p.activeClosed {
		return false
	}
	if p.activeConns == nil {
		p.activeConns = make(map[net.Conn]struct{})
	}
	p.activeConns[conn] = struct{}{}
	return true
}

func (p *proxyApp) untrackConnection(conn net.Conn) {
	p.activeMu.Lock()
	delete(p.activeConns, conn)
	p.activeMu.Unlock()
}

func (p *proxyApp) closeActiveConnections() {
	p.activeMu.Lock()
	p.activeClosed = true
	connections := make([]net.Conn, 0, len(p.activeConns))
	for conn := range p.activeConns {
		connections = append(connections, conn)
	}
	p.activeConns = nil
	p.activeMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (p *proxyApp) handleConnect(w http.ResponseWriter, r *http.Request) {
	authority := r.Host
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}
	if host == "" {
		http.Error(w, "missing CONNECT host", http.StatusBadRequest)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP hijacking is unavailable", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	if !p.trackConnection(conn) {
		_ = conn.Close()
		return
	}
	defer p.untrackConnection(conn)
	defer conn.Close()
	_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := rw.Flush(); err != nil {
		return
	}
	buffered := &bufferedConn{Conn: conn, reader: rw.Reader}
	// Look at the first byte: 0x16 is a TLS handshake. Anything else is a
	// plain HTTP request tunnelled through CONNECT (CONNECT to port 80 etc.),
	// which must not be fed to the TLS server. Browsers also open idle
	// "preconnect" tunnels; those just time out here, quietly.
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	first, err := rw.Reader.Peek(1)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	if first[0] != 0x16 {
		p.serveTunnelRequests(buffered, authority, "http")
		return
	}
	leaf, err := p.issueHostCert(host)
	if err != nil {
		log.Printf("certificate for %s: %v", host, err)
		return
	}
	tlsConn := tls.Server(buffered, &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	})
	// Bound the handshake so a browser that opens a CONNECT tunnel and then
	// goes silent doesn't leak the goroutine and file descriptor forever.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		lowerErr := strings.ToLower(err.Error())
		if strings.Contains(lowerErr, "unknown certificate") || strings.Contains(lowerErr, "bad certificate") || strings.Contains(lowerErr, "unknown ca") {
			p.noteCertRejection(host)
			return
		}
		if !isBenignTunnelErr(err) {
			log.Printf("TLS from browser for %s: %v", host, err)
		}
		return
	}
	_ = conn.SetDeadline(time.Time{})
	p.serveTunnelRequests(tlsConn, authority, "https")
}

// noteCertRejection counts a browser that refused the proxy's certificate and
// logs it at most once per host every 5 minutes.
func (p *proxyApp) noteCertRejection(host string) {
	p.certRejects.Add(1)
	p.rejectMu.Lock()
	defer p.rejectMu.Unlock()
	if p.rejectLogged == nil || len(p.rejectLogged) > 1000 {
		p.rejectLogged = make(map[string]time.Time)
	}
	if last, ok := p.rejectLogged[host]; ok && time.Since(last) < 5*time.Minute {
		return
	}
	p.rejectLogged[host] = time.Now()
	log.Printf("browser rejected the proxy certificate for %s; import the CA certificate into the browser", host)
}

// isBenignTunnelErr reports errors that are normal for browser tunnels:
// idle timeouts, resets and closes. They are not worth a log line.
func isBenignTunnelErr(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed") || strings.Contains(msg, "forcibly closed") ||
		strings.Contains(msg, "unknown certificate") || strings.Contains(msg, "bad certificate")
}

// bufferedConn preserves bytes net/http may have read ahead after CONNECT.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// idleReader refreshes the read deadline before every Read, so a body that
// stops arriving for d is cut off instead of holding the tunnel forever.
type idleReader struct {
	c net.Conn
	r io.Reader
	d time.Duration
}

func (x idleReader) Read(b []byte) (int, error) {
	_ = x.c.SetReadDeadline(time.Now().Add(x.d))
	return x.r.Read(b)
}

// deadlineWriter gives every Write its own no-progress deadline.
type deadlineWriter struct {
	c net.Conn
	d time.Duration
}

func (w deadlineWriter) Write(b []byte) (int, error) {
	_ = w.c.SetWriteDeadline(time.Now().Add(w.d))
	return w.c.Write(b)
}

func isTimeoutErr(err error) bool {
	var netErr net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

func (p *proxyApp) serveTunnelRequests(conn net.Conn, connectAuthority, scheme string) {
	defer conn.Close()
	base := p.baseCtx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	writeError := func(status int, message string) {
		_ = writeErrorResponse(deadlineWriter{conn, 30 * time.Second}, status, message)
	}
	reader := bufio.NewReader(conn)
	for {
		_ = conn.SetWriteDeadline(time.Time{})
		// Bound how long a keep-alive tunnel can sit idle waiting for the
		// next request; without this an abandoned tunnel's goroutine and
		// fd never get reclaimed. Hitting it is normal, so it isn't logged.
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !isBenignTunnelErr(err) {
				log.Printf("read tunneled request: %v", err)
			}
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		targetHost := req.Host
		if targetHost == "" {
			targetHost = connectAuthority
		}
		if scheme == "https" {
			targetHost = strings.TrimSuffix(targetHost, ":443")
		} else {
			targetHost = strings.TrimSuffix(targetHost, ":80")
		}
		target := scheme + "://" + targetHost + req.URL.RequestURI()

		// Expect: 100-continue is answered here; the relay never forwards it.
		if expect := req.Header.Get("Expect"); expect != "" {
			if !strings.EqualFold(expect, "100-continue") {
				writeError(http.StatusExpectationFailed, "expectation not supported")
				return
			}
			if req.ContentLength > maxRequestBody {
				writeError(http.StatusRequestEntityTooLarge, "request body exceeds 32 MiB limit")
				return
			}
			if req.ContentLength != 0 {
				_, _ = io.WriteString(deadlineWriter{conn, 30 * time.Second}, "HTTP/1.1 100 Continue\r\n\r\n")
			}
		}

		// Read the whole body here, with an idle timeout, before relaying.
		data, readErr := io.ReadAll(io.LimitReader(idleReader{conn, req.Body, 60 * time.Second}, maxRequestBody+1))
		_ = req.Body.Close()
		if readErr != nil {
			return
		}
		if len(data) > maxRequestBody {
			writeError(http.StatusRequestEntityTooLarge, "request body exceeds 32 MiB limit")
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		req.Body = io.NopCloser(bytes.NewReader(data))
		req.ContentLength = int64(len(data))

		// Cancel the relay if the browser closes the tunnel while GAS works.
		// Only this goroutine reads from the bufio.Reader while the relay
		// runs; it is stopped (via a read deadline) before the next request
		// is parsed. A pipelined byte simply stays buffered.
		reqCtx, reqCancel := context.WithCancel(ctx)
		req = req.WithContext(reqCtx)
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			if _, peekErr := reader.Peek(1); peekErr != nil && !isTimeoutErr(peekErr) {
				reqCancel()
			}
		}()
		resp, relayErr := p.relay(req, target)
		_ = conn.SetReadDeadline(time.Now()) // wake the Peek if it is still blocked
		<-watchDone
		_ = conn.SetReadDeadline(time.Time{})
		reqCancel()

		if relayErr != nil {
			_ = req.Body.Close()
			status, message := relayFailure(relayErr)
			writeError(status, message)
			if !errors.Is(relayErr, context.Canceled) {
				log.Printf("relay %s: %v", target, relayErr)
			}
			return
		}
		resp.Close = req.Close
		writeErr := resp.Write(deadlineWriter{conn, 2 * time.Minute})
		resp.Body.Close()
		_ = req.Body.Close()
		if writeErr != nil || req.Close {
			return
		}
	}
}

func isUpgradeRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" || connectionTokens(r.Header)["upgrade"]
}

func isIdempotentMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func (p *proxyApp) relay(in *http.Request, target string) (*http.Response, error) {
	// Fail fast, and with the right status, for things Apps Script cannot do.
	if isUpgradeRequest(in) {
		return nil, &relayStatusError{http.StatusNotImplemented, "WebSocket/Upgrade requests are not supported by the Apps Script relay"}
	}
	if len(target) > maxGASURLBytes {
		// Warn only: the quota table says ~2 KB but Google sign-in URLs are
		// longer and must still be tried; Apps Script's own answer decides.
		log.Printf("relay warning: URL is %d bytes (documented Apps Script limit ~%d), sending anyway: %.120s...", len(target), maxGASURLBytes, target)
	}
	// Refuse an oversized declared body before buffering any of it.
	if in.ContentLength > maxRequestBody {
		return nil, &relayStatusError{http.StatusRequestEntityTooLarge, "request body exceeds 32 MiB limit"}
	}
	var body []byte
	if in.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(in.Body, maxRequestBody+1))
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
	}
	if len(body) > maxRequestBody {
		return nil, &relayStatusError{http.StatusRequestEntityTooLarge, "request body exceeds 32 MiB limit"}
	}
	headers := make(map[string]string)
	headerBytes := 0
	hdr := in.Header.Clone()
	stripHopByHop(hdr)
	for name, values := range hdr {
		lower := strings.ToLower(name)
		if lower == "host" || lower == "content-length" || lower == "accept-encoding" {
			// accept-encoding: Content-Encoding is stripped from the relayed
			// response below, so ask the origin for plain content.
			continue
		}
		if len(values) > 0 {
			// RFC 6265: multiple Cookie values are joined with "; ".
			separator := ", "
			if lower == "cookie" {
				separator = "; "
			}
			value := strings.Join(values, separator)
			headers[name] = value
			headerBytes += len(name) + len(value) + 4
		}
	}
	if headerBytes > maxGASHeaderBytes {
		log.Printf("relay warning: request headers are %d bytes (documented Apps Script limit ~%d), sending anyway (%s)", headerBytes, maxGASHeaderBytes, target)
	}
	headers["Accept-Encoding"] = "identity"
	encoded, err := func() ([]byte, error) {
		return json.Marshal(relayRequest{Key: p.key, URL: target, Method: in.Method, Headers: headers, Body: base64.StdEncoding.EncodeToString(body), Redirect: false})
	}()
	if err != nil {
		return nil, fmt.Errorf("encode relay request: %w", err)
	}
	p.sentRequests.Add(1)
	p.sentBytes.Add(uint64(len(body)))
	body = nil // the JSON payload holds the only copy that is still needed

	// One context per relay: cancelled when the browser gives up, when the
	// app is stopped, or after a generous overall limit.
	base := p.baseCtx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(base, 5*time.Minute)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	if reqDone := in.Context().Done(); reqDone != nil {
		go func() {
			select {
			case <-reqDone:
				cancel()
			case <-done:
			}
		}()
	}

	attempts := 1
	if isIdempotentMethod(in.Method) {
		attempts = 3 // POST is never retried
	}
	var lastErr error
retryLoop:
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			wait := (300*time.Millisecond)<<uint(attempt) + time.Duration(mathrand.Intn(300))*time.Millisecond
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				lastErr = ctx.Err()
				break retryLoop
			}
			p.retries.Add(1)
			log.Printf("relay retry %d for %s %s after: %v", attempt, in.Method, target, lastErr)
		}
		resp, times, retryable, err := p.relayOnce(ctx, in, target, encoded)
		if err == nil {
			// Metrics are recorded once per browser request, not per attempt.
			p.recordGASSuccess(times.headers, times.full)
			return resp, nil
		}
		lastErr = err
		if !retryable || ctx.Err() != nil {
			break
		}
	}
	// A cancelled relay (browser went away, or the app is stopping) is not a
	// GAS failure; a missed deadline is.
	if !errors.Is(lastErr, context.Canceled) {
		p.recordGASFailure(lastErr.Error())
	}
	return nil, lastErr
}

// attemptTimes holds the timings of one successful GAS round trip.
type attemptTimes struct {
	headers time.Duration // until the Apps Script response headers arrived
	full    time.Duration // until the body was read, parsed and decoded
}

// looksPermanentHTML reports whether a non-JSON reply is a sign-in page or a
// quota/authorization error. Retrying those only wastes GAS quota.
func looksPermanentHTML(data []byte) bool {
	if len(data) > 64<<10 {
		data = data[:64<<10]
	}
	lower := strings.ToLower(string(data))
	for _, marker := range []string{"accounts.google.com", "servicelogin", "authorization needed", "too many times", "quota"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// relayOnce performs a single GAS round trip. retryable is true for transient
// failures (network errors, HTTP 429/5xx, non-JSON replies that are not a
// sign-in or quota page). It does not record metrics; relay() does that once
// per browser request.
func (p *proxyApp) relayOnce(ctx context.Context, in *http.Request, target string, encoded []byte) (*http.Response, attemptTimes, bool, error) {
	var times attemptTimes
	fail := func(err error, retryable bool) (*http.Response, attemptTimes, bool, error) {
		return nil, times, retryable, err
	}
	if p.relaySlots != nil {
		waitStart := time.Now()
		select {
		case p.relaySlots <- struct{}{}:
			defer func() { <-p.relaySlots }()
			p.queueWaitMS.Add(uint64(time.Since(waitStart) / time.Millisecond))
		case <-ctx.Done():
			return fail(ctx.Err(), false)
		}
	}
	// Memory held in the response budget; given back on every error path and,
	// on success, when the response body is closed.
	var held int64
	handedOff := false
	defer func() {
		if !handedOff && held > 0 {
			p.memBudget.release(held)
		}
	}()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.scriptURL, bytes.NewReader(encoded))
	if err != nil {
		return fail(err, false)
	}
	request.Header.Set("Content-Type", "application/json")
	startedAt := time.Now()
	gatewayResp, err := p.http.Do(request)
	if err != nil {
		return fail(fmt.Errorf("Apps Script request failed: %w", err), ctx.Err() == nil)
	}
	times.headers = time.Since(startedAt)
	defer gatewayResp.Body.Close()
	switch code := gatewayResp.StatusCode; {
	case code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusNotFound:
		return fail(fmt.Errorf("Apps Script returned HTTP %d: check that the deployment access is 'Anyone' and the URL is correct", code), false)
	case code == http.StatusTooManyRequests || code >= 500:
		return fail(fmt.Errorf("Apps Script returned HTTP %d", code), true)
	}
	if gatewayResp.ContentLength > maxRelayJSON {
		return fail(errors.New("relay JSON response exceeds 64 MiB client limit"), false)
	}
	// A response can briefly exist as the JSON bytes, the body string and the
	// decoded bytes, so reserve about three times its size. Acquire only
	// after the headers arrived and while holding nothing, so waiters cannot
	// deadlock; the first holder always proceeds.
	estimate := int64(24 << 20)
	if gatewayResp.ContentLength >= 0 {
		estimate = 3 * gatewayResp.ContentLength
	}
	if err := p.memBudget.acquire(ctx, estimate); err != nil {
		return fail(err, false)
	}
	held = estimate
	data, err := io.ReadAll(io.LimitReader(gatewayResp.Body, maxRelayJSON+1))
	if err != nil {
		return fail(fmt.Errorf("read Apps Script response: %w", err), true)
	}
	if len(data) > maxRelayJSON {
		return fail(errors.New("relay JSON response exceeds 64 MiB client limit"), false)
	}
	var result relayResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return fail(fmt.Errorf("Apps Script returned HTTP %d instead of relay JSON: %.300s", gatewayResp.StatusCode, data), !looksPermanentHTML(data))
	}
	data = nil
	if result.Error != "" {
		return fail(errors.New(result.Error), false)
	}
	if result.Status < 100 || result.Status > 599 {
		return fail(errors.New("relay response has an invalid upstream status"), false)
	}
	decoded, err := base64.StdEncoding.DecodeString(result.Body)
	result.Body = ""
	if err != nil {
		return fail(fmt.Errorf("decode relay response body: %w", err), false)
	}
	times.full = time.Since(startedAt)
	// Only the decoded bytes stay in memory now.
	size := int64(len(decoded))
	if held > size {
		p.memBudget.release(held - size)
	} else if size > held {
		p.memBudget.force(size - held)
	}
	held = size

	resp := &http.Response{
		StatusCode: result.Status,
		Status:     fmt.Sprintf("%d %s", result.Status, http.StatusText(result.Status)),
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: make(http.Header), Request: in,
	}
	// Headers named by the origin's Connection header are hop-by-hop too.
	nominated := make(map[string]bool)
	for name, raw := range result.Headers {
		if strings.EqualFold(name, "connection") {
			for _, value := range result.Headers.values(name, raw) {
				for _, token := range strings.Split(value, ",") {
					if token = strings.ToLower(strings.TrimSpace(token)); token != "" {
						nominated[token] = true
					}
				}
			}
		}
	}
	originLength := int64(-1)
	for name, raw := range result.Headers {
		lower := strings.ToLower(name)
		if lower == "content-length" {
			if vals := result.Headers.values(name, raw); len(vals) > 0 {
				if n, err := strconv.ParseInt(strings.TrimSpace(vals[0]), 10, 64); err == nil && n >= 0 {
					originLength = n
				}
			}
			continue
		}
		if hopByHop[lower] || nominated[lower] || lower == "content-encoding" {
			continue
		}
		// Add (not Set) one line per value so several Set-Cookie headers
		// reach the browser as separate cookies.
		for _, value := range result.Headers.values(name, raw) {
			resp.Header.Add(name, value)
		}
	}
	noBody := in.Method == http.MethodHead || result.Status == http.StatusNoContent ||
		result.Status == http.StatusNotModified || result.Status < 200
	switch {
	case in.Method == http.MethodHead && originLength >= 0 && result.Status != http.StatusNoContent && result.Status != http.StatusNotModified:
		// HEAD has no body, but must report the origin's length.
		resp.Header.Set("Content-Length", strconv.FormatInt(originLength, 10))
		resp.ContentLength = originLength
		resp.Body = http.NoBody // the deferred release gives the budget back now
	case noBody:
		resp.ContentLength = 0
		resp.Body = http.NoBody
	default:
		resp.Header.Set("Content-Length", strconv.Itoa(len(decoded)))
		resp.ContentLength = int64(len(decoded))
		resp.Body = &budgetBody{
			ReadCloser: io.NopCloser(bytes.NewReader(decoded)),
			release:    func() { p.memBudget.release(size) },
		}
		handedOff = true
	}
	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 || (result.Status >= 300 && result.Status < 400) {
		log.Printf("relay %s %s -> %d, %d Set-Cookie", in.Method, target, result.Status, len(cookies))
	}
	p.receivedResponses.Add(1)
	p.receivedBytes.Add(uint64(len(decoded)))
	return resp, times, false, nil
}

func (p *proxyApp) recordGASSuccess(firstByte, full time.Duration) {
	p.activeMu.Lock()
	if p.activeClosed {
		p.activeMu.Unlock()
		return
	}
	p.metrics.recordSuccess(firstByte, full)
	p.activeMu.Unlock()
	message := fmt.Sprintf("GAS relay responded: first byte %.0f ms, full %.0f ms.",
		float64(firstByte)/float64(time.Millisecond), float64(full)/float64(time.Millisecond))
	if p.onGASResult != nil {
		p.onGASResult(true, message)
	}
}

func (p *proxyApp) recordGASFailure(message string) {
	p.activeMu.Lock()
	if p.activeClosed {
		p.activeMu.Unlock()
		return
	}
	p.metrics.recordFailure(message)
	p.activeMu.Unlock()
	if p.onGASResult != nil {
		p.onGASResult(false, message)
	}
}

func copyHeaders(dst, src http.Header) {
	clean := src.Clone()
	stripHopByHop(clean)
	for name, values := range clean {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

// relayFailure maps a relay error to the status/message sent to the browser.
// Only the 413/501 messages are safe to show; everything else stays generic
// because raw errors can contain the GAS deployment URL.
func relayFailure(err error) (int, string) {
	var se *relayStatusError
	if errors.As(err, &se) {
		return se.status, se.msg
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return http.StatusGatewayTimeout, "proxy relay timed out"
	}
	return http.StatusBadGateway, "proxy relay failed; see local proxy logs for details"
}

func writeErrorResponse(w io.Writer, status int, message string) error {
	body := []byte(message + "\n")
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body)
	return err
}

// atomicWriteFile writes data to a temp file in the same directory as path
// and renames it into place, so a crash mid-write can't leave a corrupt or
// truncated file behind.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		// Best effort: persist the rename itself.
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	return nil
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// parsePrivateKey tries PKCS#8, PKCS#1 RSA, and SEC1 EC formats.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format (expected PKCS#8, PKCS#1 RSA, or SEC1 EC)")
}

// resolveCAPaths picks the CA certificate and key files: explicit paths,
// then the saved uploaded pair, then mycert.crt / ca.crt in dir.
func resolveCAPaths(dir, certOverride, keyOverride string) (certPath, keyPath string, explicitCert bool, err error) {
	certPath = strings.TrimSpace(certOverride)
	keyPath = strings.TrimSpace(keyOverride)
	explicitCert = certPath != ""
	if !explicitCert {
		uploadedCert, uploadedKey, uploadErr := savedUploadedCAPaths(dir)
		if uploadErr != nil {
			// Don't hard-fail startup over a stale/deleted uploaded-CA
			// manifest (e.g. its directory was removed by hand): fall back
			// to the default cert/key discovery below instead of refusing
			// to start until the user finds and fixes the manifest file.
			log.Printf("saved uploaded CA selection ignored: %v", uploadErr)
		} else if uploadedCert != "" {
			certPath = uploadedCert
			if keyPath == "" {
				keyPath = uploadedKey
			}
		}
		if certPath == "" {
			for _, candidate := range []string{
				filepath.Join(dir, "mycert.crt"),
				filepath.Join(dir, "mycert.cert"),
				filepath.Join(dir, "ca.crt"),
			} {
				if _, err := os.Stat(candidate); err == nil {
					certPath = candidate
					break
				} else if !os.IsNotExist(err) {
					return "", "", false, err
				}
			}
		}
		if certPath == "" {
			certPath = filepath.Join(dir, "ca.crt")
		}
	}
	if keyPath == "" {
		keyPath = strings.TrimSuffix(certPath, filepath.Ext(certPath)) + ".key"
	}
	return certPath, keyPath, explicitCert, nil
}

// caFileMu serializes CA file discovery and generation so a cancelled start
// that is still generating cannot interleave with the next one.
var caFileMu sync.Mutex

func loadOrCreateCA(dir, certOverride, keyOverride string) (*x509.Certificate, crypto.PrivateKey, string, string, error) {
	caFileMu.Lock()
	defer caFileMu.Unlock()
	certPath, keyPath, explicitCert, err := resolveCAPaths(dir, certOverride, keyOverride)
	if err != nil {
		return nil, nil, "", "", err
	}

	certPEM, certErr := os.ReadFile(certPath)
	if certErr == nil {
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			if os.IsNotExist(err) {
				// Never auto-generate here: that would silently invalidate the
				// CA the browser already trusts.
				return nil, nil, "", "", fmt.Errorf("CA certificate %s exists but key %s is missing. Restore the key, or delete both files to generate a new CA (you must re-import it into the browser).", certPath, keyPath)
			}
			return nil, nil, "", "", fmt.Errorf("read matching CA key %s: %w", keyPath, err)
		}
		block, _ := pem.Decode(certPEM)
		var certDER []byte
		if block != nil {
			certDER = block.Bytes
		} else {
			certDER = certPEM
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("parse CA certificate %s: %w", certPath, err)
		}
		if !cert.IsCA || (cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0) {
			return nil, nil, "", "", errors.New("selected certificate is not allowed to sign CA certificates")
		}
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return nil, nil, "", "", fmt.Errorf("selected CA certificate is not currently valid (valid %s to %s)", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
		}
		keyBlock, _ := pem.Decode(keyPEM)
		var keyDER []byte
		if keyBlock != nil {
			keyDER = keyBlock.Bytes
		} else {
			keyDER = keyPEM
		}
		key, err := parsePrivateKey(keyDER)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("parse CA key %s: %w", keyPath, err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, nil, "", "", errors.New("selected CA private key cannot sign certificates")
		}
		certPublicKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("read CA certificate public key: %w", err)
		}
		keyPublicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			return nil, nil, "", "", fmt.Errorf("read CA private key public key: %w", err)
		}
		if !bytes.Equal(certPublicKey, keyPublicKey) {
			return nil, nil, "", "", errors.New("selected certificate and private key do not match")
		}
		log.Printf("Loaded CA cert: %s, key: %s", certPath, keyPath)
		return cert, key, certPath, keyPath, nil
	}
	if !os.IsNotExist(certErr) {
		return nil, nil, "", "", certErr
	}
	if explicitCert {
		return nil, nil, "", "", fmt.Errorf("selected CA certificate does not exist: %s", certPath)
	}
	// Generate a local CA only when the default certificate files are absent.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, "", "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, "", "", err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "MedoVPN Local HTTPS Inspection CA"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		// MaxPathLenZero must be set alongside MaxPathLen: 0, or Go's x509
		// encoder treats the unset bool as "no path-length constraint"
		// instead of "path length exactly 0".
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, "", "", err
	}
	newCertPath := filepath.Join(dir, "ca.crt")
	newKeyPath := filepath.Join(dir, "ca.key")
	// Write the key first and the certificate last: the certificate file is
	// the commit marker. A crash in between leaves only an orphan key, which
	// the next start harmlessly overwrites (generation runs only while the
	// certificate is absent).
	if err := atomicWriteFile(newKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return nil, nil, "", "", err
	}
	if err := atomicWriteFile(newCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return nil, nil, "", "", err
	}
	return cert, key, newCertPath, newKeyPath, nil
}

func savedUploadedCAPaths(dir string) (string, string, error) {
	manifestPath := filepath.Join(dir, "uploaded-ca.json")
	data, err := os.ReadFile(manifestPath)
	if os.IsNotExist(err) {
		return mostRecentLegacyUploadedCA(dir)
	}
	if err != nil {
		return "", "", err
	}
	var manifest struct {
		Directory string `json:"directory"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", "", fmt.Errorf("parse %s: %w", manifestPath, err)
	}
	manifest.Directory = strings.TrimSpace(manifest.Directory)
	if manifest.Directory == "" || filepath.Base(manifest.Directory) != manifest.Directory || !strings.HasPrefix(manifest.Directory, "uploaded-ca-") {
		return "", "", errors.New("saved uploaded CA directory is invalid")
	}
	uploadDir := filepath.Join(dir, manifest.Directory)
	certPath := filepath.Join(uploadDir, "ca.crt")
	keyPath := filepath.Join(uploadDir, "ca.key")
	if _, err := os.Stat(certPath); err != nil {
		return "", "", fmt.Errorf("saved uploaded CA certificate is unavailable: %w", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		return "", "", fmt.Errorf("saved uploaded CA key is unavailable: %w", err)
	}
	return certPath, keyPath, nil
}

func mostRecentLegacyUploadedCA(dir string) (string, string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	var newestCert, newestKey string
	var newestTime time.Time
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "uploaded-ca-") {
			continue
		}
		certPath := filepath.Join(dir, entry.Name(), "ca.crt")
		keyPath := filepath.Join(dir, entry.Name(), "ca.key")
		if _, err := os.Stat(certPath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", "", err
		}
		if _, err := os.Stat(keyPath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", "", err
		}
		info, err := entry.Info()
		if err != nil {
			return "", "", err
		}
		if newestCert == "" || info.ModTime().After(newestTime) {
			newestCert, newestKey, newestTime = certPath, keyPath, info.ModTime()
		}
	}
	return newestCert, newestKey, nil
}

// hostCertEntry pairs a cached leaf certificate with the time it stops being
// safe to hand out, so a long-running proxy regenerates it instead of
// serving an expired cert forever.
type hostCertEntry struct {
	cert     tls.Certificate
	notAfter time.Time
}

// issueHostCertLocks serializes leaf-certificate generation per host so a
// burst of concurrent CONNECTs to the same host doesn't each pay the cost of
// a fresh 2048-bit RSA key generation.
var issueHostCertLocks sync.Map // host -> *sync.Mutex

const maxCachedCerts = 2000

func (p *proxyApp) issueHostCert(host string) (tls.Certificate, error) {
	const renewBefore = time.Hour
	host = strings.ToLower(host)
	if cached, ok := p.certCache.Load(host); ok {
		entry := cached.(hostCertEntry)
		if time.Until(entry.notAfter) > renewBefore {
			return entry.cert, nil
		}
	}
	lockIface, _ := issueHostCertLocks.LoadOrStore(host, &sync.Mutex{})
	lock := lockIface.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	// Free the per-host lock entry when done (runs before Unlock).
	defer issueHostCertLocks.Delete(host)
	// Re-check after acquiring the lock: another goroutine may have just
	// regenerated the certificate for this host.
	if cached, ok := p.certCache.Load(host); ok {
		entry := cached.(hostCertEntry)
		if time.Until(entry.notAfter) > renewBefore {
			return entry.cert, nil
		}
	}
	// ECDSA P-256 leaf keys are generated in microseconds; RSA-2048 took
	// 100 ms to 1 s per host, and YouTube touches dozens of hosts.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	notAfter := time.Now().Add(24 * time.Hour)
	leafTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		leafTemplate.IPAddresses = []net.IP{ip}
	} else {
		leafTemplate.DNSNames = []string{host}
	}
	// p.caKey may be RSA or ECDSA; x509.CreateCertificate handles both.
	der, err := x509.CreateCertificate(rand.Reader, leafTemplate, p.caCert, &leafKey.PublicKey, p.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	chain := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.caCert.Raw})...,
	)
	leaf, err := tls.X509KeyPair(chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}))
	if err != nil {
		return tls.Certificate{}, err
	}
	if p.certCount.Add(1) > maxCachedCerts {
		p.certCache.Range(func(k, _ any) bool { p.certCache.Delete(k); return true })
		p.certCount.Store(1)
	}
	entry := hostCertEntry{cert: leaf, notAfter: notAfter}
	p.certCache.Store(host, entry)
	return entry.cert, nil
}
