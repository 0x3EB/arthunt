// arthunt — passive secret scanner for JFrog Artifactory.
//
// Discovers repositories from a base URL, lists their files (AQL, falling back
// to the Storage API), fetches text/config artifacts within a byte budget and
// runs embedded TruffleHog/Gitleaks-style detectors entirely offline. No secret
// is ever validated against a third-party service. Designed for low-and-slow,
// authorised audits: global rate limiting, jitter, randomised order, resume.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/0x3EB/arthunt/internal/artifactory"
	"github.com/0x3EB/arthunt/internal/report"
	"github.com/0x3EB/arthunt/internal/scan"
)

// version is overridable at build time: -ldflags "-X main.version=v1.2.3".
var version = "1.0.0"

type profile struct {
	rate   float64
	conns  int
	jitter float64
}

var profiles = map[string]profile{
	"stealth":    {rate: 1.5, conns: 2, jitter: 0.5},
	"furtif":     {rate: 1.5, conns: 2, jitter: 0.5},
	"balanced":   {rate: 5, conns: 4, jitter: 0.3},
	"equilibre":  {rate: 5, conns: 4, jitter: 0.3},
	"aggressive": {rate: 20, conns: 12, jitter: 0.1},
	"soutenu":    {rate: 20, conns: 12, jitter: 0.1},
}

func main() {
	fs := flag.NewFlagSet("arthunt", flag.ContinueOnError)
	var (
		urlFlag     = fs.String("url", "", "Artifactory base URL (e.g. https://repo.corp.tld or .../artifactory) [required]")
		token       = fs.String("token", "", "Bearer access token (or env ARTHUNT_TOKEN)")
		apiKey      = fs.String("api-key", "", "X-JFrog-Art-Api-Key (or env ARTHUNT_API_KEY)")
		user        = fs.String("user", "", "username for basic auth (or env ARTHUNT_USER)")
		password    = fs.String("password", "", "password for basic auth (or env ARTHUNT_PASSWORD)")
		basic       = fs.String("basic", "", "raw base64 of 'user:password' (the value after 'Authorization: Basic '), or env ARTHUNT_BASIC")
		mintToken   = fs.Bool("mint-token", false, "exchange basic-auth creds for a short-lived access token, then scan with it")
		tokenTTL    = fs.Duration("token-ttl", 0, "lifetime of the minted token (0 = server default; e.g. 6h for long scans)")
		out         = fs.String("out", "arthunt-report", "output file prefix (writes .json/.csv/.html)")
		format      = fs.String("format", "all", "report format: all|json|csv|html")
		prof        = fs.String("profile", "stealth", "OPSEC profile: stealth|balanced|aggressive")
		rate        = fs.Float64("rate", 0, "requests/sec (overrides profile)")
		conns       = fs.Int("concurrency", 0, "concurrent connections (overrides profile)")
		jitter      = fs.Float64("jitter", -1, "rate jitter fraction 0..1 (overrides profile)")
		inclRemote  = fs.Bool("include-remote", false, "also scan remote (cache) repositories")
		inclVirtual = fs.Bool("include-virtual", false, "also scan virtual repositories")
		reposFlag   = fs.String("repos", "", "comma-separated repo allowlist (overrides type filters)")
		exclude     = fs.String("exclude", "", "comma-separated repo keys to skip")
		pkgType     = fs.String("package-type", "", "comma-separated packageType filter (e.g. maven,npm,generic)")
		maxSize     = fs.String("max-size", "5MB", "max bytes fetched per file (e.g. 512KB, 5MB)")
		crack       = fs.Bool("crack", false, "open archives (jar/war/zip/tgz/nupkg/whl...) one level deep")
		dockerCfg   = fs.Bool("docker-config", false, "for Docker repos, scan image manifests + config blobs (ENV/build-args) — not layers")
		dockerLyr   = fs.Bool("docker-layers", false, "also scan Docker image LAYERS (filesystem) — heavy; implies docker scanning")
		maxLayer    = fs.String("max-layer-size", "100MB", "max bytes fetched per Docker layer")
		noFiles     = fs.Bool("no-files", false, "skip the regular file scan; only targeted modes run (e.g. with --docker-config)")
		since       = fs.String("since", "", "only artifacts modified within this window, e.g. 7d / 24h / 2w (needs AQL)")
		decodeB64   = fs.Bool("decode-base64", true, "also scan base64-decoded blobs")
		extsFlag    = fs.String("extensions", "", "extra file extensions to scan (comma-separated)")
		extLess     = fs.Bool("extensionless", false, "also scan files with no extension")
		rulesFile   = fs.String("rules", "", "external JSON rules file to merge with built-ins")
		insecure    = fs.Bool("insecure", false, "skip TLS certificate verification")
		proxy       = fs.String("proxy", "", "proxy URL (else honours HTTP(S)_PROXY env)")
		ua          = fs.String("user-agent", "jfrog-cli-go/2.74.0", "HTTP User-Agent")
		resume      = fs.String("resume", "", "checkpoint file to skip already-scanned items and resume")
		retry       = fs.String("retry", "", "re-scan ONLY the items in a previous <out>.errors.jsonl (no re-listing)")
		merge       = fs.String("merge", "", "merge findings from a previous <out>.json into this report (rewrites it)")
		showSecrets = fs.Bool("show-secrets", false, "include full secret values in output (default: redacted)")
		minSev      = fs.String("min-severity", "", "report only >= this severity: low|medium|high|critical")
		maxFind     = fs.Int("max-findings", 0, "stop after N findings (0 = unlimited)")
		timeout     = fs.Duration("timeout", 60*time.Second, "per-request timeout")
		dryRun      = fs.Bool("dry-run", false, "list selectable files without downloading or scanning")
		failOnFind  = fs.Bool("fail-on-findings", false, "exit code 3 if any secrets are found (CI gating)")
		maxDuration = fs.Duration("max-duration", 0, "spread the scan over ~this window for max stealth (e.g. 24h); only slows, never exceeds the profile")
		noLive      = fs.Bool("no-live", false, "do not print findings live to stderr as they are discovered")
		plain       = fs.Bool("plain", false, "plain scrolling output instead of the sticky live dashboard")
		verbose     = fs.Bool("verbose", false, "verbose progress to stderr")
		showVer     = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "arthunt %s — passive Artifactory secret scanner\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n  arthunt --url https://repo.corp.tld --token $TOK [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSecrets can be passed via env (ARTHUNT_TOKEN/ARTHUNT_API_KEY/ARTHUNT_USER/ARTHUNT_PASSWORD)\nto keep them out of the process list.\n")
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *showVer {
		fmt.Printf("arthunt %s\n", version)
		return
	}

	// Secrets from env if not on the command line (avoids process-list exposure).
	*token = orEnv(*token, "ARTHUNT_TOKEN")
	*apiKey = orEnv(*apiKey, "ARTHUNT_API_KEY")
	*user = orEnv(*user, "ARTHUNT_USER")
	*password = orEnv(*password, "ARTHUNT_PASSWORD")
	*basic = orEnv(*basic, "ARTHUNT_BASIC")

	// --basic: paste the base64 'user:password' you already use (no cfg file).
	// Decoding into user/password yields the byte-identical Authorization: Basic
	// header and lets --mint-token learn the username from the hash.
	if *basic != "" && *user == "" {
		u, p, err := parseBasic(*basic)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: --basic: %v\n", err)
			os.Exit(2)
		}
		*user, *password = u, p
	}

	if *urlFlag == "" {
		fmt.Fprintln(os.Stderr, "error: --url is required")
		fs.Usage()
		os.Exit(2)
	}

	p, ok := profiles[strings.ToLower(*prof)]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unknown profile %q (use stealth|balanced|aggressive)\n", *prof)
		os.Exit(2)
	}
	if *rate > 0 {
		p.rate = *rate
	}
	if *conns > 0 {
		p.conns = *conns
	}
	if *jitter >= 0 {
		p.jitter = *jitter
	}

	maxBytes, err := parseSize(*maxSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --max-size: %v\n", err)
		os.Exit(2)
	}

	switch strings.ToLower(*format) {
	case "all", "json", "csv", "html":
	default:
		fmt.Fprintf(os.Stderr, "error: --format must be all|json|csv|html, got %q\n", *format)
		os.Exit(2)
	}

	layerBytes, err := parseSize(*maxLayer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --max-layer-size: %v\n", err)
		os.Exit(2)
	}

	var modifiedSince time.Time
	if *since != "" {
		d, derr := parseSince(*since)
		if derr != nil {
			fmt.Fprintf(os.Stderr, "error: --since: %v\n", derr)
			os.Exit(2)
		}
		modifiedSince = time.Now().Add(-d)
	}

	if *noFiles && !*dockerCfg && !*dockerLyr {
		fmt.Fprintln(os.Stderr, "error: --no-files needs a targeted mode — add --docker-config and/or --docker-layers")
		os.Exit(2)
	}

	// Surface an environment proxy so egress is never silently rerouted.
	if *proxy == "" {
		for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
			if v := os.Getenv(k); v != "" {
				fmt.Fprintf(os.Stderr, "[i] note: %s is set — traffic will route through %s (use --proxy to override)\n", k, v)
				break
			}
		}
	}

	rules, err := scan.LoadRules(*rulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "arthunt %s — profile=%s rate=%.2g/s conns=%d jitter=%.0f%% detectors=%d\n",
		version, strings.ToLower(*prof), p.rate, p.conns, p.jitter*100, len(rules))

	limiter := scan.NewLimiter(p.rate, p.jitter)

	// When minting, the handshake + mint MUST authenticate with Basic-Auth.
	// Drop any supplied token AND api-key (newRequest ranks both above Basic), or
	// the mint request would carry the wrong credential and never send Basic.
	initialToken, initialAPIKey := *token, *apiKey
	if *mintToken && (*token != "" || *apiKey != "") {
		fmt.Fprintln(os.Stderr, "[i] --mint-token set: ignoring --token/--api-key; minting from --user/--password")
		initialToken, initialAPIKey = "", ""
	}

	client, err := artifactory.New(ctx, artifactory.Options{
		BaseURL:    *urlFlag,
		Token:      initialToken,
		APIKey:     initialAPIKey,
		User:       *user,
		Password:   *password,
		UserAgent:  *ua,
		Insecure:   *insecure,
		Proxy:      *proxy,
		Pacer:      limiter,
		MaxConns:   p.conns,
		ReqTimeout: *timeout,
		MaxRetries: 4,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if v, err := client.Version(ctx); err == nil && v != "" {
		fmt.Fprintf(os.Stderr, "[i] connected: Artifactory %s at %s\n", v, client.Base())
	} else {
		fmt.Fprintf(os.Stderr, "[i] connected: %s\n", client.Base())
	}

	// Basic-Auth -> short-lived access token: send the password once to mint a
	// revocable self token, then run the whole (noisy) scan under that token.
	if *mintToken {
		if *user == "" {
			fmt.Fprintln(os.Stderr, "error: --mint-token requires --user/--password (Basic-Auth)")
			os.Exit(2)
		}
		tok, exp, err := client.MintToken(ctx, *tokenTTL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		client.UseBearer(tok)
		if exp > 0 {
			fmt.Fprintf(os.Stderr, "[i] minted access token for %q (expires in %s) — scanning under token, password not resent\n", *user, exp)
			if *tokenTTL == 0 {
				fmt.Fprintf(os.Stderr, "[i] token TTL is the server default; for a long stealth scan pass --token-ttl 6h (subject to server policy) and --resume\n")
			}
		} else {
			fmt.Fprintf(os.Stderr, "[i] minted access token for %q — scanning under token, password not resent\n", *user)
		}
	}

	eng := scan.NewEngine(client, rules, scan.Config{
		MaxFileSize:     maxBytes,
		Crack:           *crack,
		DockerConfig:    *dockerCfg,
		DockerLayers:    *dockerLyr,
		MaxLayerSize:    layerBytes,
		NoFiles:         *noFiles,
		ModifiedSince:   modifiedSince,
		DecodeBase64:    *decodeB64,
		Workers:         p.conns,
		Randomize:       true,
		ShowSecrets:     *showSecrets,
		MinSeverity:     strings.ToLower(*minSev),
		MaxFindings:     *maxFind,
		ExtraExtensions: splitCSV(*extsFlag),
		TextOnly:        !*extLess,
		ResumePath:      *resume,
		DryRun:          *dryRun,
		Verbose:         *verbose,
		Live:            !*noLive,
		Plain:           *plain,
		MaxDuration:     *maxDuration,
		Limiter:         limiter,
	})

	var findings []scan.Finding
	var stats scan.Stats
	var runErr error
	if *retry != "" {
		// Targeted retry: load the previous run's errors and re-scan only those,
		// without re-listing. Loaded up-front so writing <out>.errors.jsonl later
		// (possibly the same path) is safe.
		errs, lerr := report.LoadErrorsJSONL(*retry)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "error: --retry %s: %v\n", *retry, lerr)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[i] retry: loaded %d error record(s) from %s\n", len(errs), *retry)
		findings, stats, runErr = eng.RunRetry(ctx, errs)
	} else {
		repos, lerr := client.ListRepositories(ctx)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "error: list repositories: %v\n", lerr)
			os.Exit(1)
		}
		selected := filterRepos(repos, repoFilter{
			allow:       splitCSV(*reposFlag),
			exclude:     splitCSV(*exclude),
			pkgTypes:    splitCSV(*pkgType),
			inclRemote:  *inclRemote,
			inclVirtual: *inclVirtual,
		})
		if len(selected) == 0 {
			fmt.Fprintln(os.Stderr, "error: no repositories matched the selection")
			fmt.Fprintf(os.Stderr, "[i] %d repositories visible. Use --include-remote/--include-virtual or --repos.\n", len(repos))
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[i] %d/%d repositories selected for scanning\n", len(selected), len(repos))
		findings, stats, runErr = eng.Run(ctx, selected)
	}
	if runErr != nil && ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "[!] interrupted — writing partial report")
	} else if runErr != nil {
		// A genuine runtime error (not a signal): don't emit a misleading
		// empty/partial report — fail loudly.
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", runErr)
		os.Exit(1)
	}

	// Always surface per-item/per-repo failures so they can be inspected and
	// replayed (--retry). Written even on an interrupted run.
	scanErrs := eng.ScanErrors()
	ep := *out + ".errors.jsonl"
	if len(scanErrs) > 0 {
		if werr := report.WriteErrorsJSONL(ep, scanErrs); werr != nil {
			fmt.Fprintf(os.Stderr, "[!] could not write errors file %s: %v\n", ep, werr)
		} else {
			fmt.Fprintf(os.Stderr, "[i] %d error(s) → %s  (replay with: --retry %s)\n", len(scanErrs), ep, ep)
		}
	} else if !*dryRun {
		// No errors this run: clear any stale errors file so the retry loop
		// converges (a successful --retry empties it).
		if _, statErr := os.Stat(ep); statErr == nil {
			os.Remove(ep)
			fmt.Fprintf(os.Stderr, "[i] no errors — cleared %s\n", ep)
		}
	}

	if *dryRun {
		fmt.Fprintf(os.Stderr, "[i] dry-run: %d file(s) would be scanned\n", stats.FilesSelected)
		return
	}

	// Merge with a previous report's findings (rewrite fresh reports — appending
	// in place to HTML/CSV/JSON is not reliable).
	if *merge != "" {
		if prior, merr := report.LoadJSON(*merge); merr != nil {
			fmt.Fprintf(os.Stderr, "[!] --merge %s: %v (using this run's findings only)\n", *merge, merr)
		} else {
			before := len(findings)
			findings = mergeFindings(prior.Findings, findings)
			fmt.Fprintf(os.Stderr, "[i] merged %d prior + %d new → %d unique findings\n", len(prior.Findings), before, len(findings))
			stats.Findings = len(findings)
		}
	}

	rep := report.Report{
		Meta: report.Meta{
			Tool:        "arthunt",
			Version:     version,
			Target:      client.Base(),
			RulesetVer:  scan.RulesetVersion(),
			RuleCount:   len(rules),
			GeneratedAt: time.Now(),
			Profile:     strings.ToLower(*prof),
		},
		Stats:    stats,
		Findings: findings,
	}
	if err := writeReports(*out, *format, rep); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing report: %v\n", err)
		os.Exit(1)
	}

	printSummary(os.Stderr, rep, *out, *format)

	// Exit codes: 0 clean, 1 runtime error, 2 usage (above), 3 findings (only
	// when --fail-on-findings is set, for CI gating). A signal-interrupted run
	// still wrote a partial report and exits 0.
	if runErr != nil && ctx.Err() == nil {
		os.Exit(1)
	}
	if *failOnFind && len(findings) > 0 {
		os.Exit(3)
	}
}

func writeReports(prefix, format string, rep report.Report) error {
	format = strings.ToLower(format)
	want := func(f string) bool { return format == "all" || format == f }
	if want("json") {
		if err := report.WriteJSON(prefix+".json", rep); err != nil {
			return err
		}
	}
	if want("csv") {
		if err := report.WriteCSV(prefix+".csv", rep); err != nil {
			return err
		}
	}
	if want("html") {
		if err := report.WriteHTML(prefix+".html", rep); err != nil {
			return err
		}
	}
	return nil
}

func printSummary(w *os.File, rep report.Report, prefix, format string) {
	bySev := map[string]int{}
	for _, f := range rep.Findings {
		bySev[f.Severity]++
	}
	fmt.Fprintf(w, "\n===== arthunt summary =====\n")
	fmt.Fprintf(w, "repos=%d files=%d/%d bytes=%d errors=%d duration=%s\n",
		rep.Stats.ReposScanned, rep.Stats.FilesScanned, rep.Stats.FilesSelected,
		rep.Stats.BytesDownloaded, rep.Stats.Errors, rep.Stats.Duration)
	fmt.Fprintf(w, "findings: %d  (critical=%d high=%d medium=%d low=%d)\n",
		len(rep.Findings), bySev["critical"], bySev["high"], bySev["medium"], bySev["low"])
	format = strings.ToLower(format)
	for _, f := range []string{"json", "csv", "html"} {
		if format == "all" || format == f {
			fmt.Fprintf(w, "report: %s.%s\n", prefix, f)
		}
	}
}

// parseBasic decodes a base64 'user:password' blob (optionally prefixed with
// "Basic ") into its parts — the exact value used in an Authorization: Basic
// header — so the operator can paste the credential they already have.
func parseBasic(s string) (user, pass string, err error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "Basic ")
	s = strings.TrimPrefix(s, "basic ")
	s = strings.TrimSpace(s)
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", "", fmt.Errorf("not valid base64: %w", err)
	}
	u, p, ok := strings.Cut(string(dec), ":")
	if !ok {
		return "", "", fmt.Errorf("decoded value is not 'user:password'")
	}
	return u, p, nil
}

// parseSince parses a window like "7d", "24h", "2w", "90m" into a Duration.
// Go's time.ParseDuration lacks day/week units, so handle those explicitly.
func parseSince(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		v, err := strconv.ParseFloat(n, 64)
		if err != nil || v <= 0 {
			return 0, fmt.Errorf("invalid days %q", s)
		}
		return time.Duration(v * float64(24*time.Hour)), nil
	}
	if n, ok := strings.CutSuffix(s, "w"); ok {
		v, err := strconv.ParseFloat(n, 64)
		if err != nil || v <= 0 {
			return 0, fmt.Errorf("invalid weeks %q", s)
		}
		return time.Duration(v * float64(7*24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s) // h/m/s
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q (use e.g. 7d, 24h, 2w)", s)
	}
	return d, nil
}

// mergeFindings concatenates prior and new findings, de-duplicated by stable
// Fingerprint (falling back to a composite key if absent). Prior entries win.
func mergeFindings(prior, current []scan.Finding) []scan.Finding {
	seen := make(map[string]bool, len(prior)+len(current))
	out := make([]scan.Finding, 0, len(prior)+len(current))
	for _, set := range [][]scan.Finding{prior, current} {
		for _, f := range set {
			k := f.Fingerprint
			if k == "" {
				k = f.RuleID + "|" + f.Repo + "|" + f.Path + "|" + f.Match
			}
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func orEnv(v, key string) string {
	if v != "" {
		return v
	}
	return os.Getenv(key)
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "GB") || strings.HasSuffix(s, "G"):
		mult = 1 << 30
		s = strings.TrimRight(s, "GB")
	case strings.HasSuffix(s, "MB") || strings.HasSuffix(s, "M"):
		mult = 1 << 20
		s = strings.TrimRight(s, "MB")
	case strings.HasSuffix(s, "KB") || strings.HasSuffix(s, "K"):
		mult = 1 << 10
		s = strings.TrimRight(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimRight(s, "B")
	}
	s = strings.TrimSpace(s)
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	v := int64(n * float64(mult))
	if v <= 0 {
		return 0, fmt.Errorf("size must be positive, got %q", s)
	}
	return v, nil
}

type repoFilter struct {
	allow       []string
	exclude     []string
	pkgTypes    []string
	inclRemote  bool
	inclVirtual bool
}

func filterRepos(repos []artifactory.Repo, f repoFilter) []artifactory.Repo {
	allow := toSet(f.allow)
	excl := toSet(f.exclude)
	pkgs := toLowerSet(f.pkgTypes)
	var out []artifactory.Repo
	for _, r := range repos {
		if excl[r.Key] {
			continue
		}
		if len(allow) > 0 {
			if !allow[r.Key] {
				continue
			}
		} else {
			switch strings.ToUpper(r.Type) {
			case "LOCAL", "FEDERATED":
				// always included
			case "REMOTE":
				if !f.inclRemote {
					continue
				}
			case "VIRTUAL":
				if !f.inclVirtual {
					continue
				}
			default:
				if !f.inclRemote && !f.inclVirtual {
					continue
				}
			}
		}
		if len(pkgs) > 0 && !pkgs[strings.ToLower(r.PackageType)] {
			continue
		}
		out = append(out, r)
	}
	return out
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func toLowerSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[strings.ToLower(x)] = true
	}
	return m
}
