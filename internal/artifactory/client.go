// Package artifactory is a minimal, stdlib-only JFrog Artifactory REST client
// geared toward read-only auditing: repository discovery, item listing (AQL with
// a Storage-API fallback) and byte-capped artifact retrieval. Every request is
// paced through a caller-supplied Waiter so the whole tool stays within an OPSEC
// rate budget.
package artifactory

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Waiter paces requests (implemented by scan.Limiter). It must block until the
// next request is allowed or the context is cancelled.
type Waiter interface {
	Wait(ctx context.Context) error
}

// ErrNotFound is returned for HTTP 404 responses.
var ErrNotFound = errors.New("not found")

// ErrForbidden is returned for 401/403 (auth or permission problems).
var ErrForbidden = errors.New("unauthorized or forbidden")

// Options configures a Client.
type Options struct {
	BaseURL    string
	Token      string // Bearer access token
	APIKey     string // X-JFrog-Art-Api-Key
	User       string // basic auth user
	Password   string // basic auth password (or API key as password)
	UserAgent  string
	Insecure   bool   // skip TLS verification
	Proxy      string // explicit proxy URL ("" => use environment)
	Pacer      Waiter // request pacing (rate limit + jitter)
	MaxConns   int    // max concurrent connections per host
	ReqTimeout time.Duration
	MaxRetries int
}

// Client talks to one Artifactory instance.
type Client struct {
	base string
	opt  Options
	hc   *http.Client
}

// Repo is a repository descriptor from /api/repositories.
type Repo struct {
	Key         string `json:"key"`
	Type        string `json:"type"`        // LOCAL / REMOTE / VIRTUAL / FEDERATED
	PackageType string `json:"packageType"` // maven, npm, docker, generic, ...
}

// Item is a file entry within a repository.
type Item struct {
	Repo   string
	Path   string // folder path ("." for repo root)
	Name   string
	Size   int64
	Sha256 string
}

// FullPath returns the repo-relative path of the item ("path/name").
func (it Item) FullPath() string {
	if it.Path == "" || it.Path == "." {
		return it.Name
	}
	return it.Path + "/" + it.Name
}

// New builds a Client and normalises the base URL by probing /api/system/ping.
func New(ctx context.Context, o Options) (*Client, error) {
	if o.MaxConns <= 0 {
		o.MaxConns = 4
	}
	if o.ReqTimeout <= 0 {
		o.ReqTimeout = 60 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = "jfrog-cli-go/2.74.0"
	}

	tr := &http.Transport{
		MaxIdleConns:          o.MaxConns * 2,
		MaxConnsPerHost:       o.MaxConns,
		MaxIdleConnsPerHost:   o.MaxConns,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if o.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if o.Proxy != "" {
		pu, err := url.Parse(o.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid --proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	} else {
		tr.Proxy = http.ProxyFromEnvironment
	}

	c := &Client{
		opt: o,
		hc: &http.Client{
			Transport: tr,
			// PASSIVITY: never follow a redirect that leaves the target host.
			// Artifactory's "Direct Cloud Storage Download" answers artifact GETs
			// with a 302 to a signed S3/Azure/GCS URL; following it would leak the
			// operator's source IP + DNS to a third party outside the engagement.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 && req.URL.Host != via[0].URL.Host {
					return http.ErrUseLastResponse // hand the 3xx back, don't follow
				}
				if len(via) >= 10 {
					return errors.New("stopped after 10 redirects")
				}
				return nil
			},
		},
	}

	base := strings.TrimRight(o.BaseURL, "/")
	if base == "" {
		return nil, errors.New("empty base URL")
	}
	// Probe base as given, then with an /artifactory suffix (JFrog Platform).
	candidates := []string{base}
	if !strings.HasSuffix(base, "/artifactory") {
		candidates = append(candidates, base+"/artifactory")
	}
	var lastErr error
	for _, cand := range candidates {
		c.base = cand
		if err := c.Ping(ctx); err != nil {
			lastErr = err
			continue
		}
		return c, nil
	}
	return nil, fmt.Errorf("could not reach Artifactory at %s (tried %v): %w", o.BaseURL, candidates, lastErr)
}

// Base returns the resolved base URL.
func (c *Client) Base() string { return c.base }

func (c *Client) newRequest(ctx context.Context, method, fullURL string, body io.Reader, contentType string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.opt.UserAgent)
	// Accept anything: /api/system/ping returns text/plain ("OK"), and some
	// WAFs/proxies reply 406 Not Acceptable to a strict "application/json".
	// JSON endpoints return JSON regardless, and we parse by content not header.
	req.Header.Set("Accept", "*/*")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	switch {
	case c.opt.Token != "":
		req.Header.Set("Authorization", "Bearer "+c.opt.Token)
	case c.opt.APIKey != "":
		req.Header.Set("X-JFrog-Art-Api-Key", c.opt.APIKey)
	case c.opt.User != "":
		req.SetBasicAuth(c.opt.User, c.opt.Password)
	}
	return req, nil
}

// do executes a request with pacing and retry on 429/5xx. The caller owns the
// returned body and must close it (which also releases the per-request context).
// bodyBytes (if non-nil) is replayable for retries.
func (c *Client) do(ctx context.Context, method, fullURL string, bodyBytes []byte, contentType string) (*http.Response, error) {
	retries := c.opt.MaxRetries
	if retries < 0 {
		retries = 0
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if c.opt.Pacer != nil {
			if err := c.opt.Pacer.Wait(ctx); err != nil {
				return nil, err
			}
		}
		reqCtx, cancel := context.WithTimeout(ctx, c.opt.ReqTimeout)
		var rdr io.Reader
		if bodyBytes != nil {
			rdr = bytes.NewReader(bodyBytes)
		}
		req, err := c.newRequest(reqCtx, method, fullURL, rdr, contentType)
		if err != nil {
			cancel()
			return nil, err
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			if backoff(ctx, attempt) {
				continue
			}
			return nil, err
		}

		switch {
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			wait := retryAfter(resp)
			drain(resp)
			cancel()
			lastErr = fmt.Errorf("%s %s: HTTP %d", method, fullURL, resp.StatusCode)
			if attempt < retries {
				if !sleepCtx(ctx, wait) {
					return nil, ctx.Err()
				}
				continue
			}
			return nil, lastErr
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			drain(resp)
			cancel()
			return nil, fmt.Errorf("%s %s: %w (HTTP %d)", method, fullURL, ErrForbidden, resp.StatusCode)
		case resp.StatusCode == http.StatusNotFound:
			drain(resp)
			cancel()
			return nil, fmt.Errorf("%s %s: %w", method, fullURL, ErrNotFound)
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			loc := resp.Header.Get("Location")
			drain(resp)
			cancel()
			return nil, fmt.Errorf("%s %s: refused off-host redirect (HTTP %d) to %s — preserving passivity", method, fullURL, resp.StatusCode, redirectHost(loc))
		case resp.StatusCode >= 400:
			snippet := readSnippet(resp)
			cancel()
			return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, fullURL, resp.StatusCode, snippet)
		}
		// Success. Wrap body so the per-request context is cancelled on close.
		resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, lastErr
}

// platformBase returns the JFrog Platform root (one level up from /artifactory),
// where sibling services such as Access live.
func (c *Client) platformBase() string {
	if strings.HasSuffix(c.base, "/artifactory") {
		return strings.TrimSuffix(c.base, "/artifactory")
	}
	return c.base
}

// MintToken exchanges the configured Basic-Auth credentials for a short-lived
// access token scoped to the caller's own permissions. The noisy scan then runs
// under that revocable token instead of resending the password on every request.
// Works for a normal (non-admin) account creating a self token. Returns the
// token and its lifetime (0 = server default / non-expiring).
func (c *Client) MintToken(ctx context.Context, ttl time.Duration) (string, time.Duration, error) {
	if c.opt.User == "" {
		return "", 0, errors.New("token minting requires --user and --password (Basic-Auth)")
	}
	secs := int(ttl.Seconds())

	// 1) Classic Artifactory endpoint — a non-admin may create a token for self.
	f1 := url.Values{}
	f1.Set("username", c.opt.User)
	if secs > 0 {
		f1.Set("expires_in", strconv.Itoa(secs))
	}
	if tok, exp, err := c.postToken(ctx, c.base+"/api/security/token", f1); err == nil {
		return tok, exp, nil
	} else {
		firstErr := err
		// Wrong credentials won't be fixed by the fallback — fail fast and do
		// NOT re-send the password to a second endpoint.
		if errors.Is(firstErr, ErrForbidden) {
			return "", 0, fmt.Errorf("token minting rejected (check --user/--password): %w", firstErr)
		}
		// 2) JFrog Platform Access API.
		f2 := url.Values{}
		f2.Set("username", c.opt.User)
		f2.Set("scope", "applied-permissions/user")
		if secs > 0 {
			f2.Set("expires_in", strconv.Itoa(secs))
		}
		if tok, exp, err2 := c.postToken(ctx, c.platformBase()+"/access/api/v1/tokens", f2); err2 == nil {
			return tok, exp, nil
		} else {
			return "", 0, fmt.Errorf("token minting failed (artifactory: %v) (access: %v)", firstErr, err2)
		}
	}
}

func (c *Client) postToken(ctx context.Context, fullURL string, form url.Values) (string, time.Duration, error) {
	resp, err := c.do(ctx, http.MethodPost, fullURL, []byte(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", 0, fmt.Errorf("decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", 0, errors.New("response contained no access_token")
	}
	return tr.AccessToken, time.Duration(tr.ExpiresIn) * time.Second, nil
}

// UseBearer switches the client to Bearer-token auth, dropping any Basic/API-key
// credentials so the password is no longer sent on subsequent requests.
func (c *Client) UseBearer(token string) {
	c.opt.Token = token
	c.opt.APIKey = ""
	c.opt.User = ""
	c.opt.Password = ""
}

// Ping verifies connectivity and auth (anonymous ping is usually allowed).
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, c.base+"/api/system/ping", nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// Version returns the Artifactory version string (best effort).
func (c *Client) Version(ctx context.Context) (string, error) {
	resp, err := c.do(ctx, http.MethodGet, c.base+"/api/system/version", nil, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var v struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&v); err != nil {
		return "", err
	}
	return v.Version, nil
}

// ListRepositories returns all repositories visible to the credentials.
func (c *Client) ListRepositories(ctx context.Context) ([]Repo, error) {
	resp, err := c.do(ctx, http.MethodGet, c.base+"/api/repositories", nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var repos []Repo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<24)).Decode(&repos); err != nil {
		return nil, fmt.Errorf("decode repositories: %w", err)
	}
	return repos, nil
}

// aqlResult mirrors the AQL response envelope.
type aqlResult struct {
	Results []struct {
		Repo   string `json:"repo"`
		Path   string `json:"path"`
		Name   string `json:"name"`
		Size   int64  `json:"size"`
		Sha256 string `json:"sha256"`
	} `json:"results"`
	Range struct {
		Total int `json:"total"`
	} `json:"range"`
}

// ListItemsAQL lists every file in a repo via AQL, paginating server-side.
// pageSize bounds memory; emit is called per item. Requires AQL permission.
// When modifiedSince is non-zero, only artifacts modified at/after that time are
// listed (server-side filter).
func (c *Client) ListItemsAQL(ctx context.Context, repo string, pageSize int, modifiedSince time.Time, emit func(Item) error) error {
	if pageSize <= 0 {
		pageSize = 1000
	}
	criteria := fmt.Sprintf(`"repo":%q,"type":"file"`, repo)
	if !modifiedSince.IsZero() {
		criteria += fmt.Sprintf(`,"modified":{"$gt":%q}`, modifiedSince.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	offset := 0
	pages := 0
	for {
		q := fmt.Sprintf(
			`items.find({%s}).include("repo","path","name","size","sha256").sort({"$asc":["path","name"]}).offset(%d).limit(%d)`,
			criteria, offset, pageSize)
		resp, err := c.do(ctx, http.MethodPost, c.base+"/api/search/aql", []byte(q), "text/plain")
		if err != nil {
			return err
		}
		var res aqlResult
		dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<28))
		decErr := dec.Decode(&res)
		resp.Body.Close()
		if decErr != nil {
			return fmt.Errorf("decode AQL page (repo %s, offset %d): %w", repo, offset, decErr)
		}
		for _, r := range res.Results {
			it := Item{Repo: r.Repo, Path: r.Path, Name: r.Name, Size: r.Size, Sha256: r.Sha256}
			if it.Repo == "" {
				it.Repo = repo
			}
			if err := emit(it); err != nil {
				return err
			}
		}
		// IMPORTANT: AQL applies permission filtering AFTER the retrieval limit,
		// so a page can return fewer than pageSize rows while more readable rows
		// exist at higher offsets (the common non-admin case). Therefore advance
		// the cursor by the requested pageSize (pre-filter window), NOT by the
		// post-filter row count, and only stop on an empty page or once we pass
		// the reported total. A hard page cap guards against a server that
		// ignores offset (which would otherwise loop forever).
		got := len(res.Results)
		if got == 0 {
			break
		}
		offset += pageSize
		if res.Range.Total > 0 && offset >= res.Range.Total {
			break
		}
		pages++
		if pages > aqlMaxPages {
			fmt.Fprintf(os.Stderr, "[!] AQL pagination cap reached for %q; listing may be truncated\n", repo)
			break
		}
	}
	return nil
}

// aqlMaxPages bounds pagination so a misbehaving server that ignores offset
// cannot spin forever. At pageSize=1000 this allows up to ~2e9 listed items.
const aqlMaxPages = 2_000_000

// storageList mirrors /api/storage?list&deep=1.
type storageList struct {
	Files []struct {
		URI    string `json:"uri"`
		Size   int64  `json:"size"`
		Folder bool   `json:"folder"`
		Sha2   string `json:"sha2"`
	} `json:"files"`
}

// ListItemsStorage lists files via the Storage API (works with plain read
// permission, no AQL/admin needed). Used as a fallback when AQL is denied.
func (c *Client) ListItemsStorage(ctx context.Context, repo string, emit func(Item) error) error {
	u := fmt.Sprintf("%s/api/storage/%s/?list&deep=1&listFolders=0&mdTimestamps=0&includeRootPath=0",
		c.base, url.PathEscape(repo))
	resp, err := c.do(ctx, http.MethodGet, u, nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var sl storageList
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<28)).Decode(&sl); err != nil {
		return fmt.Errorf("decode storage list (repo %s): %w", repo, err)
	}
	for _, f := range sl.Files {
		if f.Folder {
			continue
		}
		rel := strings.TrimPrefix(f.URI, "/")
		path, name := splitPath(rel)
		if err := emit(Item{Repo: repo, Path: path, Name: name, Size: f.Size, Sha256: f.Sha2}); err != nil {
			return err
		}
	}
	return nil
}

// ArtifactURL returns the properly path-escaped browse/download URL for an
// artifact, so reported URLs match what Download actually fetches.
func (c *Client) ArtifactURL(repo, fullPath string) string {
	return c.base + "/" + url.PathEscape(repo) + "/" + escapePath(fullPath)
}

// Download fetches an artifact, returning at most maxBytes of its content.
func (c *Client) Download(ctx context.Context, it Item, maxBytes int64) ([]byte, error) {
	u := c.ArtifactURL(it.Repo, it.FullPath())
	resp, err := c.doGetRange(ctx, u, maxBytes)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var reader io.Reader = resp.Body
	if maxBytes > 0 {
		reader = io.LimitReader(resp.Body, maxBytes)
	}
	return io.ReadAll(reader)
}

func (c *Client) doGetRange(ctx context.Context, fullURL string, maxBytes int64) (*http.Response, error) {
	retries := c.opt.MaxRetries
	if retries < 0 {
		retries = 0
	}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if c.opt.Pacer != nil {
			if err := c.opt.Pacer.Wait(ctx); err != nil {
				return nil, err
			}
		}
		reqCtx, cancel := context.WithTimeout(ctx, c.opt.ReqTimeout)
		req, err := c.newRequest(reqCtx, http.MethodGet, fullURL, nil, "")
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("Accept", "*/*")
		if maxBytes > 0 {
			req.Header.Set("Range", "bytes=0-"+strconv.FormatInt(maxBytes-1, 10))
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			if backoff(ctx, attempt) {
				continue
			}
			return nil, err
		}
		switch {
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			wait := retryAfter(resp)
			drain(resp)
			cancel()
			lastErr = fmt.Errorf("GET %s: HTTP %d", fullURL, resp.StatusCode)
			if attempt < retries {
				if !sleepCtx(ctx, wait) {
					return nil, ctx.Err()
				}
				continue
			}
			return nil, lastErr
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			drain(resp)
			cancel()
			return nil, fmt.Errorf("GET %s: %w", fullURL, ErrForbidden)
		case resp.StatusCode == http.StatusNotFound:
			drain(resp)
			cancel()
			return nil, fmt.Errorf("GET %s: %w", fullURL, ErrNotFound)
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			loc := resp.Header.Get("Location")
			drain(resp)
			cancel()
			return nil, fmt.Errorf("GET %s: refused off-host redirect (HTTP %d) to %s — preserving passivity", fullURL, resp.StatusCode, redirectHost(loc))
		case resp.StatusCode >= 400:
			snip := readSnippet(resp)
			cancel()
			return nil, fmt.Errorf("GET %s: HTTP %d: %s", fullURL, resp.StatusCode, snip)
		}
		resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("download failed")
	}
	return nil, lastErr
}

// --- helpers ---

// cancelBody cancels its request context exactly once when the body is closed,
// so streaming responses release resources even though callers close resp.Body.
type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.cancel)
	return err
}

func drain(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
}

func readSnippet(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 160))
	resp.Body.Close()
	// Collapse to a single trimmed line so reflected target content can't spill
	// multi-line data into operator logs.
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

func retryAfter(resp *http.Response) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 2 * time.Second
}

func backoff(ctx context.Context, attempt int) bool {
	d := time.Duration(1<<uint(attempt)) * 500 * time.Millisecond
	if d > 10*time.Second {
		d = 10 * time.Second
	}
	return sleepCtx(ctx, d)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// redirectHost returns only the host of a redirect Location, never the full
// (possibly credential-bearing, signed) URL, for safe logging.
func redirectHost(loc string) string {
	if loc == "" {
		return "(no location)"
	}
	if u, err := url.Parse(loc); err == nil && u.Host != "" {
		return u.Host
	}
	return "(off-host)"
}

func splitPath(rel string) (path, name string) {
	i := strings.LastIndexByte(rel, '/')
	if i < 0 {
		return ".", rel
	}
	return rel[:i], rel[i+1:]
}

// escapePath percent-encodes each path segment while keeping '/' separators.
func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}
