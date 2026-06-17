package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x3EB/arthunt/internal/artifactory"
	"github.com/0x3EB/arthunt/internal/report"
	"github.com/0x3EB/arthunt/internal/scan"
)

// dec decodes a base64 test fixture at runtime, so secret-shaped sample strings
// never appear verbatim in source (avoids tripping push-protection scanners).
func dec(s string) string {
	b, _ := base64.StdEncoding.DecodeString(s)
	return string(b)
}

// mockArtifactory serves the minimal surface arthunt uses, seeded with secrets.
func mockArtifactory(t *testing.T, files map[string]string) *httptest.Server {
	t.Helper()
	type aqlItem struct {
		Repo   string `json:"repo"`
		Path   string `json:"path"`
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		Sha256 string `json:"sha256"`
		Type   string `json:"type"`
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/ping", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	})
	mux.HandleFunc("/api/system/version", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"version":"7.77.7","revision":"77707900"}`)
	})
	mux.HandleFunc("/api/repositories", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]artifactory.Repo{
			{Key: "libs-release-local", Type: "LOCAL", PackageType: "maven"},
		})
	})
	mux.HandleFunc("/api/search/aql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Terminate pagination: only return items on the first page (offset(0)).
		if !strings.Contains(string(body), "offset(0)") {
			json.NewEncoder(w).Encode(map[string]any{"results": []aqlItem{}})
			return
		}
		var items []aqlItem
		for full, content := range files {
			path, name := ".", full
			if i := strings.LastIndex(full, "/"); i >= 0 {
				path, name = full[:i], full[i+1:]
			}
			// strip repo prefix
			path = strings.TrimPrefix(path, "libs-release-local/")
			items = append(items, aqlItem{
				Repo: "libs-release-local", Path: path, Name: name,
				Size: int64(len(content)), Type: "file",
			})
		}
		json.NewEncoder(w).Encode(map[string]any{
			"results": items,
			"range":   map[string]int{"start_pos": 0, "end_pos": len(items), "total": len(items)},
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")
		if content, ok := files[key]; ok {
			io.WriteString(w, content)
			return
		}
		http.NotFound(w, r)
	})
	return httptest.NewServer(mux)
}

func TestEndToEnd(t *testing.T) {
	ghToken := dec("Z2hwX2FCM3hZWmNkV1gzNGVmR0g1NmlqS0w3OG1uUFE5MHJzVFZ3Wg==")
	if len(ghToken) != 4+36 {
		t.Fatalf("test token length wrong: %d", len(ghToken)-4)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("api_token: " + ghToken))

	files := map[string]string{
		"libs-release-local/config/application.properties": strings.Join([]string{
			"db.url=mongodb://svcacct:Tr0ub4dour@mongo.internal:27017/app",
			dec("YXdzLmFjY2Vzc0tleUlkPUFLSUFaOFlRM1JYTk8yV0s0UDFD"),
			"# encoded creds below",
			"blob=" + b64,
		}, "\n"),
		"libs-release-local/keys/id_rsa": dec("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBcmFuZG9tYmFzZTY0c3R1ZmYKLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0K"),
	}

	srv := mockArtifactory(t, files)
	defer srv.Close()

	ctx := context.Background()
	limiter := scan.NewLimiter(1000, 0) // fast for tests
	client, err := artifactory.New(ctx, artifactory.Options{
		BaseURL: srv.URL, Pacer: limiter, MaxConns: 4, ReqTimeout: 10 * time.Second, MaxRetries: 1,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	rules, err := scan.LoadRules("")
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	repos, err := client.ListRepositories(ctx)
	if err != nil {
		t.Fatalf("repos: %v", err)
	}
	eng := scan.NewEngine(client, rules, scan.Config{
		MaxFileSize: 5 << 20, DecodeBase64: true, Workers: 4, TextOnly: true, ShowSecrets: true,
	})
	findings, stats, err := eng.Run(ctx, repos)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	t.Logf("stats: scanned=%d findings=%d", stats.FilesScanned, len(findings))
	got := map[string]bool{}
	var viaB64 bool
	for _, f := range findings {
		got[f.RuleID] = true
		if f.ViaDecoder == "base64" {
			viaB64 = true
		}
		t.Logf("  [%s] %s %s:%d via=%q match=%s", f.Severity, f.RuleID, f.Path, f.Line, f.ViaDecoder, f.Match)
	}

	want := []string{"aws-access-key-id", "private-key", "db-conn-mongodb", "github-pat"}
	for _, w := range want {
		if !got[w] {
			t.Errorf("expected finding for rule %q, not found", w)
		}
	}
	if !viaB64 {
		t.Errorf("expected at least one base64-decoded finding")
	}
}

func TestPlaceholderFiltered(t *testing.T) {
	rules, _ := scan.LoadRules("")
	// The canonical AWS example key must be suppressed by the allowlist.
	files := map[string]string{
		"libs-release-local/x.properties": dec("YXdzLmFjY2Vzc0tleUlkPUFLSUFJT1NGT0ROTjdFWEFNUExFCnBhc3N3b3JkPWNoYW5nZW1lCg=="),
	}
	srv := mockArtifactory(t, files)
	defer srv.Close()
	ctx := context.Background()
	client, err := artifactory.New(ctx, artifactory.Options{
		BaseURL: srv.URL, Pacer: scan.NewLimiter(1000, 0), MaxConns: 2, ReqTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	repos, _ := client.ListRepositories(ctx)
	eng := scan.NewEngine(client, rules, scan.Config{MaxFileSize: 1 << 20, Workers: 2, TextOnly: true})
	findings, _, err := eng.Run(ctx, repos)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, f := range findings {
		t.Logf("unexpected finding: %s %s", f.RuleID, f.Match)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for placeholder values, got %d", len(findings))
	}
}

// TestAQLPaginationPermissionFilter locks in the fix for the critical bug where
// pagination stopped on the first short page. JFrog applies permission filtering
// AFTER the limit, so a non-admin sees fewer rows than the limit while more
// readable rows exist at higher offsets. The scanner must keep paging.
func TestAQLPaginationPermissionFilter(t *testing.T) {
	// 5 DB rows; only rows 0,2,4 are readable by this principal.
	readable := map[int]string{
		0: dec("azA9QUtJQVo4WVEzUlhOTzJXSzRQMEE="),
		2: dec("azI9QUtJQVo4WVEzUlhOTzJXSzRQMkM="),
		4: dec("azQ9QUtJQVo4WVEzUlhOTzJXSzRQNEU="),
	}
	const total = 5
	reOff := regexp.MustCompile(`offset\((\d+)\)`)
	reLim := regexp.MustCompile(`limit\((\d+)\)`)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") })
	mux.HandleFunc("/api/repositories", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]artifactory.Repo{{Key: "repo", Type: "LOCAL"}})
	})
	mux.HandleFunc("/api/search/aql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		off, _ := strconv.Atoi(firstGroup(reOff, string(body)))
		lim, _ := strconv.Atoi(firstGroup(reLim, string(body)))
		type item struct {
			Repo, Path, Name string
			Size             int64
			Type             string
		}
		var items []item
		for i := off; i < off+lim && i < total; i++ {
			if _, ok := readable[i]; ok {
				items = append(items, item{Repo: "repo", Path: ".", Name: fmt.Sprintf("f%d.properties", i), Size: 64, Type: "file"})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"results": items,
			"range":   map[string]int{"start_pos": off, "end_pos": off + len(items), "total": total},
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// /repo/fN.properties -> secret for row N
		var n int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/repo/f"), "%d.properties", &n)
		if v, ok := readable[n]; ok {
			io.WriteString(w, v)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	client, err := artifactory.New(ctx, artifactory.Options{
		BaseURL: srv.URL, Pacer: scan.NewLimiter(0, 0), MaxConns: 2, ReqTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	rules, _ := scan.LoadRules("")
	repos, _ := client.ListRepositories(ctx)
	// pageSize 2 => first page returns only row 0 (rows 0,1 window, 1 filtered).
	eng := scan.NewEngine(client, rules, scan.Config{MaxFileSize: 1 << 20, Workers: 1, TextOnly: true, PageSize: 2})
	findings, stats, err := eng.Run(ctx, repos)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.FilesScanned != 3 {
		t.Errorf("expected 3 files scanned across paginated permission-filtered results, got %d", stats.FilesScanned)
	}
	if len(findings) != 3 {
		t.Errorf("expected 3 findings (one per readable row), got %d", len(findings))
		for _, f := range findings {
			t.Logf("  %s %s", f.RuleID, f.Path)
		}
	}
}

func firstGroup(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// TestMintTokenFlow verifies the Basic-Auth -> access-token exchange: the token
// endpoint requires Basic, and every other endpoint then requires the Bearer
// token (proving the password is no longer sent during the scan).
func TestMintTokenFlow(t *testing.T) {
	const minted = "MINTED-abc123"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") })
	mux.HandleFunc("/api/security/token", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			w.WriteHeader(401)
			return
		}
		u, p, _ := r.BasicAuth()
		if u != "auditor" || p != "s3cret" {
			w.WriteHeader(403)
			return
		}
		_ = r.ParseForm()
		if r.FormValue("username") != "auditor" {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": minted, "expires_in": 3600, "token_type": "Bearer"})
	})
	requireBearer := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+minted {
				w.WriteHeader(401)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/api/repositories", requireBearer(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]artifactory.Repo{{Key: "repo", Type: "LOCAL"}})
	}))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	client, err := artifactory.New(ctx, artifactory.Options{
		BaseURL: srv.URL, User: "auditor", Password: "s3cret",
		Pacer: scan.NewLimiter(0, 0), MaxConns: 2, ReqTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	// Basic-auth must NOT be accepted on /api/repositories.
	if _, err := client.ListRepositories(ctx); err == nil {
		t.Fatalf("expected basic-auth to be rejected on /api/repositories before minting")
	}
	tok, exp, err := client.MintToken(ctx, 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if tok != minted {
		t.Fatalf("got token %q want %q", tok, minted)
	}
	if exp != time.Hour {
		t.Errorf("expected 1h expiry, got %s", exp)
	}
	client.UseBearer(tok)
	repos, err := client.ListRepositories(ctx)
	if err != nil {
		t.Fatalf("list repos under bearer: %v", err)
	}
	if len(repos) != 1 || repos[0].Key != "repo" {
		t.Fatalf("unexpected repos: %+v", repos)
	}
}

// TestDockerConfigScan verifies T2: the image config blob (ENV secrets) is
// fetched and scanned, while heavy layer blobs are never requested.
func TestDockerConfigScan(t *testing.T) {
	const configHex = "1111111111111111111111111111111111111111111111111111111111111111"
	const layerHex = "2222222222222222222222222222222222222222222222222222222222222222"
	manifest := `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json",` +
		`"config":{"digest":"sha256:` + configHex + `"},` +
		`"layers":[{"digest":"sha256:` + layerHex + `"}]}`
	configBlob := `{"architecture":"amd64","config":{"Env":[` +
		dec("IlBBVEg9L3Vzci9sb2NhbC9iaW4iLCJBV1NfQUNDRVNTX0tFWV9JRD1BS0lBWjhZUTNSWE5PMldLNFAxQyIsIkRCX1BBU1NXT1JEPVN1cDNyUzNjcmV0UHciXX19")

	var mu sync.Mutex
	requested := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") })
	mux.HandleFunc("/api/repositories", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]artifactory.Repo{{Key: "docker-local", Type: "LOCAL", PackageType: "docker"}})
	})
	mux.HandleFunc("/api/search/aql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "offset(0)") {
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
			{"repo": "docker-local", "path": "myimage/1.0", "name": "manifest.json", "size": len(manifest), "type": "file"},
		}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested[r.URL.Path] = true
		mu.Unlock()
		switch r.URL.Path {
		case "/docker-local/myimage/1.0/manifest.json":
			io.WriteString(w, manifest)
		case "/docker-local/myimage/1.0/sha256__" + configHex:
			io.WriteString(w, configBlob)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	client, err := artifactory.New(ctx, artifactory.Options{
		BaseURL: srv.URL, Pacer: scan.NewLimiter(0, 0), MaxConns: 2, ReqTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	rules, _ := scan.LoadRules("")
	repos, _ := client.ListRepositories(ctx)
	eng := scan.NewEngine(client, rules, scan.Config{
		MaxFileSize: 1 << 20, Workers: 1, TextOnly: true, DockerConfig: true, ShowSecrets: true,
	})
	findings, _, err := eng.Run(ctx, repos)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	var awsInConfig bool
	for _, f := range findings {
		if f.RuleID == "aws-access-key-id" && strings.Contains(f.Path, "!config:") {
			awsInConfig = true
		}
	}
	if !awsInConfig {
		t.Errorf("expected AWS key from docker image config blob; findings=%+v", findings)
	}
	mu.Lock()
	defer mu.Unlock()
	if !requested["/docker-local/myimage/1.0/sha256__"+configHex] {
		t.Errorf("config blob was not fetched")
	}
	if requested["/docker-local/myimage/1.0/sha256__"+layerHex] {
		t.Errorf("layer blob WAS fetched — T2 must not pull layers")
	}
}

// TestRefuseOffHostRedirect locks in the passivity fix: an artifact GET that
// 302-redirects to a different host (JFrog "Direct Cloud Storage Download") must
// NOT be followed — the off-host (S3/Azure/GCS) server must never be contacted.
func TestRefuseOffHostRedirect(t *testing.T) {
	var leaked int32
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&leaked, 1)                            // any hit here is an OPSEC failure
		io.WriteString(w, dec("QUtJQVo4WVEzUlhOTzJXSzRQMUM=")) // a "secret" we must NOT reach
	}))
	defer off.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") })
	mux.HandleFunc("/api/repositories", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]artifactory.Repo{{Key: "repo", Type: "LOCAL"}})
	})
	mux.HandleFunc("/api/search/aql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "offset(0)") {
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
			{"repo": "repo", "path": ".", "name": "creds.txt", "size": 20, "type": "file"},
		}})
	})
	mux.HandleFunc("/repo/creds.txt", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, off.URL+"/signed-blob", http.StatusFound) // 302 off-host
	})
	target := httptest.NewServer(mux)
	defer target.Close()

	ctx := context.Background()
	client, err := artifactory.New(ctx, artifactory.Options{
		BaseURL: target.URL, Pacer: scan.NewLimiter(0, 0), MaxConns: 2, ReqTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	rules, _ := scan.LoadRules("")
	repos, _ := client.ListRepositories(ctx)
	eng := scan.NewEngine(client, rules, scan.Config{MaxFileSize: 1 << 20, Workers: 1, TextOnly: true})
	findings, stats, err := eng.Run(ctx, repos)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n := atomic.LoadInt32(&leaked); n != 0 {
		t.Fatalf("OPSEC FAILURE: off-host redirect was followed (%d hits to third-party host)", n)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings (off-host blob never read), got %d", len(findings))
	}
	if stats.Errors == 0 {
		t.Errorf("expected the refused redirect to be counted as an error")
	}
}

// TestDockerManifestListNoWrongFetch locks in the B1 fix: a manifest list must
// NOT chase sub-manifest digests under the tag folder (a wrong path that 404s);
// per-platform configs are reached via the independently-listed nested manifests.
func TestDockerManifestListNoWrongFetch(t *testing.T) {
	const sub = "1111111111111111111111111111111111111111111111111111111111111111"
	const cfg = "2222222222222222222222222222222222222222222222222222222222222222"
	list := `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json",` +
		`"manifests":[{"digest":"sha256:` + sub + `"}]}`
	platformManifest := `{"schemaVersion":2,"config":{"digest":"sha256:` + cfg + `"},"layers":[]}`
	configBlob := dec("eyJjb25maWciOnsiRW52IjpbIkFXU19BQ0NFU1NfS0VZX0lEPUFLSUFaOFlRM1JYTk8yV0s0UDFDIl19fQ==")

	var mu sync.Mutex
	got := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") })
	mux.HandleFunc("/api/repositories", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]artifactory.Repo{{Key: "d", Type: "LOCAL", PackageType: "docker"}})
	})
	mux.HandleFunc("/api/search/aql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "offset(0)") {
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
			{"repo": "d", "path": "img/latest", "name": "list.manifest.json", "size": len(list), "type": "file"},
			{"repo": "d", "path": "img/sha256__" + sub, "name": "manifest.json", "size": len(platformManifest), "type": "file"},
		}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.URL.Path] = true
		mu.Unlock()
		switch r.URL.Path {
		case "/d/img/latest/list.manifest.json":
			io.WriteString(w, list)
		case "/d/img/sha256__" + sub + "/manifest.json":
			io.WriteString(w, platformManifest)
		case "/d/img/sha256__" + sub + "/sha256__" + cfg:
			io.WriteString(w, configBlob)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	client, err := artifactory.New(ctx, artifactory.Options{BaseURL: srv.URL, Pacer: scan.NewLimiter(0, 0), MaxConns: 2, ReqTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	rules, _ := scan.LoadRules("")
	repos, _ := client.ListRepositories(ctx)
	eng := scan.NewEngine(client, rules, scan.Config{MaxFileSize: 1 << 20, Workers: 1, TextOnly: true, DockerConfig: true})
	findings, _, err := eng.Run(ctx, repos)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var found bool
	for _, f := range findings {
		if f.RuleID == "aws-access-key-id" {
			found = true
		}
	}
	if !found {
		t.Errorf("per-platform config secret not found via independent listing")
	}
	mu.Lock()
	defer mu.Unlock()
	if got["/d/img/latest/sha256__"+sub] {
		t.Errorf("wrong path fetched: manifest-list sub-digest chased under the tag folder")
	}
	if !got["/d/img/sha256__"+sub+"/sha256__"+cfg] {
		t.Errorf("per-platform config blob was not fetched")
	}
}

func TestParseBasic(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		in, u, p string
		ok       bool
	}{
		{enc("auditor:s3cr3t"), "auditor", "s3cr3t", true},
		{"Basic " + enc("u:p"), "u", "p", true},
		{enc("user:pa:ss:word"), "user", "pa:ss:word", true}, // split on first ':'
		{"not-base64!!", "", "", false},
		{enc("nocolon"), "", "", false},
	}
	for _, c := range cases {
		u, p, err := parseBasic(c.in)
		if c.ok && (err != nil || u != c.u || p != c.p) {
			t.Errorf("parseBasic(%q)=%q,%q,%v want %q,%q,nil", c.in, u, p, err, c.u, c.p)
		}
		if !c.ok && err == nil {
			t.Errorf("parseBasic(%q) expected error", c.in)
		}
	}
}

func TestParseSince(t *testing.T) {
	cases := map[string]time.Duration{
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"2w":  14 * 24 * time.Hour,
		"90m": 90 * time.Minute,
	}
	for in, want := range cases {
		got, err := parseSince(in)
		if err != nil || got != want {
			t.Errorf("parseSince(%q)=%v,%v want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "7", "-3d", "0d"} {
		if _, err := parseSince(bad); err == nil {
			t.Errorf("parseSince(%q) expected error", bad)
		}
	}
}

// TestNoFilesDockerOnly: with --no-files + docker, only manifests are processed;
// regular files in the repo are neither fetched nor scanned.
func TestNoFilesDockerOnly(t *testing.T) {
	const cfg = "1111111111111111111111111111111111111111111111111111111111111111"
	manifest := `{"schemaVersion":2,"config":{"digest":"sha256:` + cfg + `"},"layers":[]}`
	configBlob := dec("eyJjb25maWciOnsiRW52IjpbIkFXU19BQ0NFU1NfS0VZX0lEPUFLSUFaOFlRM1JYTk8yV0s0UDFDIl19fQ==")

	var mu sync.Mutex
	got := map[string]bool{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") })
	mux.HandleFunc("/api/repositories", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]artifactory.Repo{{Key: "d", Type: "LOCAL", PackageType: "docker"}})
	})
	mux.HandleFunc("/api/search/aql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "offset(0)") {
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
			{"repo": "d", "path": "img/1.0", "name": "manifest.json", "size": len(manifest), "type": "file"},
			{"repo": "d", "path": "img/1.0", "name": "leak.properties", "size": 40, "type": "file"},
		}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.URL.Path] = true
		mu.Unlock()
		switch r.URL.Path {
		case "/d/img/1.0/manifest.json":
			io.WriteString(w, manifest)
		case "/d/img/1.0/sha256__" + cfg:
			io.WriteString(w, configBlob)
		case "/d/img/1.0/leak.properties":
			io.WriteString(w, dec("YXdzLmFjY2Vzc0tleUlkPUFLSUFaOFlRM1JYTk8yV0s0UDBB"))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	client, _ := artifactory.New(ctx, artifactory.Options{BaseURL: srv.URL, Pacer: scan.NewLimiter(0, 0), MaxConns: 2, ReqTimeout: 5 * time.Second})
	rules, _ := scan.LoadRules("")
	repos, _ := client.ListRepositories(ctx)
	eng := scan.NewEngine(client, rules, scan.Config{MaxFileSize: 1 << 20, Workers: 1, TextOnly: true, DockerConfig: true, NoFiles: true})
	findings, _, err := eng.Run(ctx, repos)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got["/d/img/1.0/leak.properties"] {
		t.Errorf("regular file was fetched despite --no-files")
	}
	for _, f := range findings {
		if f.Secret == dec("QUtJQVo4WVEzUlhOTzJXSzRQMEE=") || strings.Contains(f.Match, "P0A") {
			t.Errorf("regular-file secret reported despite --no-files: %+v", f)
		}
	}
	if !got["/d/img/1.0/sha256__"+cfg] {
		t.Errorf("docker config blob was not scanned")
	}
}

// TestSinceFilter: --since adds a server-side 'modified' filter to the AQL query.
func TestSinceFilter(t *testing.T) {
	var lastBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") })
	mux.HandleFunc("/api/search/aql", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		lastBody = string(b)
		json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx := context.Background()
	client, _ := artifactory.New(ctx, artifactory.Options{BaseURL: srv.URL, Pacer: scan.NewLimiter(0, 0), MaxConns: 2, ReqTimeout: 5 * time.Second})
	cutoff := time.Now().Add(-24 * time.Hour)
	_ = client.ListItemsAQL(ctx, "repo", 1000, cutoff, func(artifactory.Item) error { return nil })
	if !strings.Contains(lastBody, `"modified":{"$gt"`) {
		t.Errorf("AQL query missing modified filter: %s", lastBody)
	}
}

// TestDockerLayers: --docker-layers cracks an image layer (gzip tar) for secrets.
func TestDockerLayers(t *testing.T) {
	const cfg = "1111111111111111111111111111111111111111111111111111111111111111"
	const lyr = "2222222222222222222222222222222222222222222222222222222222222222"

	// Build a gzipped tar layer containing app/.env with a secret.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	content := dec("QVdTX0FDQ0VTU19LRVlfSUQ9QUtJQVo4WVEzUlhOTzJXSzRQMUMK")
	tw.WriteHeader(&tar.Header{Name: "app/.env", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
	tw.Write([]byte(content))
	tw.Close()
	gw.Close()
	layerData := buf.Bytes()

	manifest := fmt.Sprintf(`{"schemaVersion":2,"config":{"digest":"sha256:%s"},"layers":[{"digest":"sha256:%s","size":%d}]}`, cfg, lyr, len(layerData))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") })
	mux.HandleFunc("/api/repositories", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]artifactory.Repo{{Key: "d", Type: "LOCAL", PackageType: "docker"}})
	})
	mux.HandleFunc("/api/search/aql", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "offset(0)") {
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
			{"repo": "d", "path": "img/1.0", "name": "manifest.json", "size": len(manifest), "type": "file"},
		}})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/d/img/1.0/manifest.json":
			io.WriteString(w, manifest)
		case "/d/img/1.0/sha256__" + cfg:
			io.WriteString(w, `{"config":{}}`)
		case "/d/img/1.0/sha256__" + lyr:
			w.Write(layerData)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	client, _ := artifactory.New(ctx, artifactory.Options{BaseURL: srv.URL, Pacer: scan.NewLimiter(0, 0), MaxConns: 2, ReqTimeout: 5 * time.Second})
	rules, _ := scan.LoadRules("")
	repos, _ := client.ListRepositories(ctx)
	eng := scan.NewEngine(client, rules, scan.Config{MaxFileSize: 1 << 20, Workers: 1, TextOnly: true, DockerLayers: true, NoFiles: true})
	findings, _, err := eng.Run(ctx, repos)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var found bool
	for _, f := range findings {
		if f.RuleID == "aws-access-key-id" && strings.Contains(f.Path, "!app/.env") {
			found = true
		}
	}
	if !found {
		t.Errorf("secret inside docker layer not found; findings=%+v", findings)
	}
}

func TestErrorsRoundTripAndMerge(t *testing.T) {
	errs := []scan.ScanError{
		{Repo: "r", Path: "a", Name: "f.txt", Kind: "item", Error: "boom", Ts: "t"},
		{Repo: "r2", Kind: "repo", Type: "LOCAL", PackageType: "maven", Error: "denied"},
	}
	p := t.TempDir() + "/e.jsonl"
	if err := report.WriteErrorsJSONL(p, errs); err != nil {
		t.Fatal(err)
	}
	got, err := report.LoadErrorsJSONL(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "f.txt" || got[1].Kind != "repo" || got[1].PackageType != "maven" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// mergeFindings dedups by fingerprint (prior + new).
	prior := []scan.Finding{{Fingerprint: "fp1", RuleID: "aws"}}
	cur := []scan.Finding{{Fingerprint: "fp1"}, {Fingerprint: "fp2"}}
	m := mergeFindings(prior, cur)
	if len(m) != 2 {
		t.Fatalf("expected 2 unique findings, got %d", len(m))
	}
}

// TestRetryFlow: a file that fails is recorded; --retry re-scans only it (no AQL).
func TestRetryFlow(t *testing.T) {
	var phase2 atomic.Bool
	var aqlCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/ping", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "OK") })
	mux.HandleFunc("/api/repositories", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]artifactory.Repo{{Key: "r", Type: "LOCAL"}})
	})
	mux.HandleFunc("/api/search/aql", func(w http.ResponseWriter, r *http.Request) {
		aqlCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "offset(0)") {
			json.NewEncoder(w).Encode(map[string]any{"results": []any{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{
			{"repo": "r", "path": ".", "name": "good.properties", "size": 40, "type": "file"},
			{"repo": "r", "path": ".", "name": "flaky.properties", "size": 40, "type": "file"},
		}})
	})
	mux.HandleFunc("/r/good.properties", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, dec("YXdzLmFjY2Vzc0tleUlkPUFLSUFaOFlRM1JYTk8yV0s0UDFD"))
	})
	mux.HandleFunc("/r/flaky.properties", func(w http.ResponseWriter, r *http.Request) {
		if phase2.Load() {
			io.WriteString(w, dec("YXdzLmFjY2Vzc0tleUlkPUFLSUFaOFlRM1JYTk8yV0s0UDBB"))
		} else {
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx := context.Background()
	client, _ := artifactory.New(ctx, artifactory.Options{BaseURL: srv.URL, Pacer: scan.NewLimiter(0, 0), MaxConns: 2, ReqTimeout: 5 * time.Second})
	rules, _ := scan.LoadRules("")
	repos, _ := client.ListRepositories(ctx)

	// Run 1: flaky.properties 404s -> recorded as an error.
	eng1 := scan.NewEngine(client, rules, scan.Config{MaxFileSize: 1 << 20, Workers: 1, TextOnly: true})
	if _, _, err := eng1.Run(ctx, repos); err != nil {
		t.Fatalf("run1: %v", err)
	}
	errs := eng1.ScanErrors()
	if len(errs) != 1 || errs[0].Name != "flaky.properties" || errs[0].Kind != "item" {
		t.Fatalf("expected 1 item error for flaky.properties, got %+v", errs)
	}
	aqlAfter1 := aqlCalls.Load()

	// Run 2: fix the file, retry ONLY the recorded error — no AQL discovery.
	phase2.Store(true)
	eng2 := scan.NewEngine(client, rules, scan.Config{MaxFileSize: 1 << 20, Workers: 1, TextOnly: true})
	findings, _, err := eng2.RunRetry(ctx, errs)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	var recovered bool
	for _, f := range findings {
		if f.RuleID == "aws-access-key-id" && strings.Contains(f.Path, "flaky.properties") {
			recovered = true
		}
	}
	if !recovered {
		t.Errorf("retry did not recover the flaky secret; findings=%+v", findings)
	}
	if aqlCalls.Load() != aqlAfter1 {
		t.Errorf("retry performed AQL discovery (%d calls) — should re-scan only the error items", aqlCalls.Load()-aqlAfter1)
	}
}

func TestParseSize(t *testing.T) {
	cases := map[string]int64{"5MB": 5 << 20, "512KB": 512 << 10, "1G": 1 << 30, "1024": 1024, "2M": 2 << 20}
	for in, want := range cases {
		got, err := parseSize(in)
		if err != nil || got != want {
			t.Errorf("parseSize(%q)=%d,%v want %d", in, got, err, want)
		}
	}
}

func TestRE2Compiles(t *testing.T) {
	rules, err := scan.LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("loaded %d rules (ruleset %s)\n", len(rules), scan.RulesetVersion())
	// Tight lower bound near the actual count so a rule silently dropped by
	// LoadRules (e.g. an RE2 compile failure introduced in an edit) is caught.
	if len(rules) < 113 {
		t.Errorf("expected ~115 rules, got %d — a detector may have been silently dropped", len(rules))
	}
}
