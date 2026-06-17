package scan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/0x3EB/arthunt/internal/artifactory"
)

// Config controls a scan run.
type Config struct {
	MaxFileSize     int64
	Crack           bool
	DecodeBase64    bool
	Workers         int
	Randomize       bool
	ShowSecrets     bool
	MinSeverity     string
	MaxFindings     int
	ExtraExtensions []string
	TextOnly        bool
	ResumePath      string
	DryRun          bool
	Verbose         bool
	PageSize        int
	DockerConfig    bool          // T2: parse Docker manifests and scan image config blobs (env/build-args)
	DockerLayers    bool          // T3: also scan Docker image layer filesystems (implies docker)
	MaxLayerSize    int64         // max bytes fetched per Docker layer (0 = default)
	NoFiles         bool          // skip the regular file scan; only targeted modes run
	ModifiedSince   time.Time     // only list artifacts modified at/after this time (zero = all)
	Live            bool          // print findings to stderr as they are discovered
	Plain           bool          // force plain line output (no sticky dashboard) even on a TTY
	MaxDuration     time.Duration // spread the scan over ~this wall-clock window (0 = profile rate)
	Limiter         *Limiter      // the shared pacer, so MaxDuration can slow it after listing
}

// dockerActive reports whether any Docker scanning mode is enabled.
func (c Config) dockerActive() bool { return c.DockerConfig || c.DockerLayers }

// Stats summarises a run.
type Stats struct {
	ReposScanned    int    `json:"repos_scanned"`
	FilesListed     int    `json:"files_listed"`
	FilesSelected   int    `json:"files_selected"`
	FilesScanned    int    `json:"files_scanned"`
	FilesSkipped    int    `json:"files_skipped"`
	BytesDownloaded int64  `json:"bytes_downloaded"`
	Findings        int    `json:"findings"`
	Errors          int    `json:"errors"`
	Duration        string `json:"duration"`
}

// ScanError records a single failure (per-item or per-repo) so it can be shown
// in <out>.errors.jsonl and replayed with --retry.
type ScanError struct {
	Repo        string `json:"repo"`
	Path        string `json:"path,omitempty"` // repo-relative path ("" for repo-level)
	Name        string `json:"name,omitempty"`
	Sha256      string `json:"sha256,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Kind        string `json:"kind"`                   // item | archive | docker | repo
	Type        string `json:"type,omitempty"`         // repo type (Kind=="repo")
	PackageType string `json:"package_type,omitempty"` // repo packageType (Kind=="repo")
	Error       string `json:"error"`
	Ts          string `json:"ts"`
}

// Engine runs detectors over an Artifactory instance.
type Engine struct {
	c     *artifactory.Client
	rules []Rule
	cfg   Config
	sel   *selector

	mu       sync.Mutex
	findings []Finding
	seenFP   map[string]bool

	errMu sync.Mutex
	errs  []ScanError

	resumeMu   sync.Mutex
	resumeFile *os.File
	resumeSeen map[string]bool

	dockerRepos map[string]bool
	dockerMu    sync.Mutex
	dockerSeen  map[string]bool // blob digests already fetched (cross-image dedup)

	dash          *dashboard
	repoMu        sync.Mutex
	repoRemaining map[string]int // selected files left to process per repo
	reposTotal    int            // repos that contain at least one selected file
	reposDone     atomic.Int64

	stat struct {
		filesProcessed  atomic.Int64
		filesScanned    atomic.Int64
		filesSkipped    atomic.Int64
		bytesDownloaded atomic.Int64
		errors          atomic.Int64
		findings        atomic.Int64
		sevCrit         atomic.Int64
		sevHigh         atomic.Int64
		sevMed          atomic.Int64
		sevLow          atomic.Int64
	}
}

// NewEngine builds an engine.
func NewEngine(c *artifactory.Client, rules []Rule, cfg Config) *Engine {
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = 1000
	}
	if cfg.MaxFileSize <= 0 {
		// 0 is NOT "unlimited" — that would allow unbounded in-memory reads.
		cfg.MaxFileSize = 5 << 20
	}
	if cfg.MaxLayerSize <= 0 {
		cfg.MaxLayerSize = 100 << 20 // layers are big; per-entry still capped by MaxFileSize
	}
	sel := newSelector(cfg.TextOnly, cfg.Crack, cfg.ExtraExtensions)
	sel.noFiles = cfg.NoFiles
	sel.docker = cfg.dockerActive()
	return &Engine{
		c:             c,
		rules:         rules,
		cfg:           cfg,
		sel:           sel,
		seenFP:        make(map[string]bool),
		resumeSeen:    make(map[string]bool),
		dockerRepos:   make(map[string]bool),
		dockerSeen:    make(map[string]bool),
		repoRemaining: make(map[string]int),
	}
}

// Run lists then scans the given repositories, returning findings + stats.
func (e *Engine) Run(ctx context.Context, repos []artifactory.Repo) ([]Finding, Stats, error) {
	start := time.Now()
	if err := e.loadResume(); err != nil {
		return nil, Stats{}, err
	}
	defer e.closeResume()

	// Record which repos are Docker, so T2 only chases image config blobs there.
	for _, r := range repos {
		if strings.EqualFold(r.PackageType, "docker") {
			e.dockerRepos[r.Key] = true
		}
	}

	// --- listing phase (paced, sequential) ---
	items := e.list(ctx, repos)
	if e.cfg.Randomize {
		rand.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
	}
	fmt.Fprintf(os.Stderr, "[i] %d file(s) selected for scanning across %d repo(s)\n", len(items), len(repos))

	if e.cfg.DryRun {
		for _, it := range items {
			fmt.Printf("%s/%s\t%d\n", it.Repo, it.FullPath(), it.Size)
		}
		st := e.statsSnapshot(start, len(repos))
		st.FilesListed = len(items)
		st.FilesSelected = len(items)
		return nil, st, ctx.Err()
	}

	return e.scanItems(ctx, items, start, len(repos))
}

// scanItems runs the scan phase (pacing window, dashboard, worker pool, finalize)
// over a prepared item list. Shared by Run (full discovery) and RunRetry.
func (e *Engine) scanItems(ctx context.Context, items []artifactory.Item, start time.Time, reposCount int) ([]Finding, Stats, error) {
	// Spread the (paced) download phase over the requested window for stealth.
	// SlowTo only ever slows down, never exceeds the chosen profile rate.
	if e.cfg.MaxDuration > 0 && e.cfg.Limiter != nil && len(items) > 0 {
		if secs := e.cfg.MaxDuration.Seconds(); secs > 0 {
			rate := float64(len(items)) / secs
			e.cfg.Limiter.SlowTo(rate)
			fmt.Fprintf(os.Stderr, "[i] spreading %d files over ~%s (≈ %.3g req/s, capped by profile)\n",
				len(items), e.cfg.MaxDuration, rate)
		}
	}

	// Per-repo remaining counts so "repos done X/Y" can advance even though files
	// are scanned in a globally shuffled (stealthy) order: a repo is "done" when
	// its last selected file has been processed.
	for _, it := range items {
		e.repoRemaining[it.Repo]++
	}
	e.reposTotal = len(e.repoRemaining)
	total := len(items)

	// --- scan phase (worker pool) ---
	// runCtx lets us stop the feeder and workers cleanly when MaxFindings is hit,
	// independently of the parent (signal) context — prevents the feeder leaking.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Sticky dashboard on a real terminal; plain line output otherwise (piped to
	// a file, --plain, or --no-live). Data always lands in the report regardless.
	if e.cfg.Live && !e.cfg.Plain && !e.cfg.DryRun {
		if tty, width := initTerminal(os.Stderr); tty {
			e.dash = newDashboard(os.Stderr, width)
			e.dash.setHeader(e.headerLines(total, start))
			defer e.dash.close()
		}
	}

	// Live progress heartbeat so a slow (stealth) scan visibly advances instead
	// of looking frozen between the "selected" line and the final summary.
	progressDone := make(chan struct{})
	go func() {
		interval := 30 * time.Second
		if e.dash != nil {
			interval = time.Second
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-progressDone:
				return
			case <-t.C:
				if e.dash != nil {
					e.dash.setHeader(e.headerLines(total, start))
				} else {
					done := e.stat.filesProcessed.Load()
					fmt.Fprintf(os.Stderr, "[i] progress: %d/%d files (%.0f%%) · %d findings · %d errors\n",
						done, total, pct(done, int64(total)), e.stat.findings.Load(), e.stat.errors.Load())
				}
			}
		}
	}()
	defer close(progressDone)

	jobs := make(chan artifactory.Item)
	var wg sync.WaitGroup
	for i := 0; i < e.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range jobs {
				if runCtx.Err() != nil {
					return
				}
				e.scanItem(runCtx, it)
				if e.cfg.MaxFindings > 0 && int(e.stat.findings.Load()) >= e.cfg.MaxFindings {
					cancel() // unblock the feeder and sibling workers
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, it := range items {
			select {
			case jobs <- it:
			case <-runCtx.Done():
				return
			}
		}
	}()
	wg.Wait()

	// Finalize: collapse overlapping detections of the same secret, then apply
	// redaction (or reveal, with --show-secrets) as a single pass.
	e.mu.Lock()
	out := e.findings
	e.mu.Unlock()
	out = dedupeBySecret(out)
	e.finalizeFindings(out)
	sortFindings(out)

	st := e.statsSnapshot(start, reposCount)
	st.FilesListed = len(items)
	st.FilesSelected = len(items)
	st.Findings = len(out)
	return out, st, ctx.Err()
}

// RunRetry re-scans only the items/repos that failed in a previous run (loaded
// from <out>.errors.jsonl), without re-listing the whole instance. Per-file
// errors become direct downloads; repo-level (listing) failures re-list just
// that repo.
func (e *Engine) RunRetry(ctx context.Context, errs []ScanError) ([]Finding, Stats, error) {
	start := time.Now()
	if err := e.loadResume(); err != nil {
		return nil, Stats{}, err
	}
	defer e.closeResume()

	var items []artifactory.Item
	var relist []artifactory.Repo
	seenRepo := map[string]bool{}
	for _, se := range errs {
		if se.Kind == "repo" {
			if !seenRepo[se.Repo] {
				seenRepo[se.Repo] = true
				r := artifactory.Repo{Key: se.Repo, Type: se.Type, PackageType: se.PackageType}
				relist = append(relist, r)
				if strings.EqualFold(r.PackageType, "docker") {
					e.dockerRepos[r.Key] = true
				}
			}
			continue
		}
		items = append(items, artifactory.Item{Repo: se.Repo, Path: se.Path, Name: se.Name, Size: se.Size, Sha256: se.Sha256})
	}
	if len(relist) > 0 {
		items = append(items, e.list(ctx, relist)...)
	}
	if e.cfg.Randomize {
		rand.Shuffle(len(items), func(i, j int) { items[i], items[j] = items[j], items[i] })
	}
	fmt.Fprintf(os.Stderr, "[i] retry: %d item(s) to re-scan\n", len(items))
	if e.cfg.DryRun {
		for _, it := range items {
			fmt.Printf("%s/%s\t%d\n", it.Repo, it.FullPath(), it.Size)
		}
		st := e.statsSnapshot(start, distinctRepos(items))
		st.FilesListed = len(items)
		st.FilesSelected = len(items)
		return nil, st, ctx.Err()
	}
	return e.scanItems(ctx, items, start, distinctRepos(items))
}

func distinctRepos(items []artifactory.Item) int {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it.Repo] = struct{}{}
	}
	return len(m)
}

func pct(a, b int64) float64 {
	if b <= 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

// markRepoDone decrements a repo's remaining file count and, when it reaches
// zero, counts the repo as finished (works under global-shuffle ordering).
func (e *Engine) markRepoDone(repo string) {
	e.repoMu.Lock()
	if n, ok := e.repoRemaining[repo]; ok {
		n--
		e.repoRemaining[repo] = n
		if n <= 0 {
			delete(e.repoRemaining, repo)
			e.reposDone.Add(1)
		}
	}
	e.repoMu.Unlock()
}

// headerLines builds the sticky dashboard header.
func (e *Engine) headerLines(total int, start time.Time) []string {
	done := e.stat.filesProcessed.Load()
	elapsed := time.Since(start)
	eta := "—"
	if done > 0 && int64(total) > done {
		per := elapsed / time.Duration(done)
		eta = fmtDur(per * time.Duration(int64(total)-done))
	} else if total > 0 && done >= int64(total) {
		eta = "0s"
	}
	return []string{
		fmt.Sprintf("arthunt · repos %d/%d done · files %d/%d (%.0f%%)",
			e.reposDone.Load(), e.reposTotal, done, total, pct(done, int64(total))),
		fmt.Sprintf("secrets: crit %d · high %d · med %d · low %d   (errors %d)",
			e.stat.sevCrit.Load(), e.stat.sevHigh.Load(), e.stat.sevMed.Load(), e.stat.sevLow.Load(), e.stat.errors.Load()),
		fmt.Sprintf("elapsed %s · eta %s", fmtDur(elapsed), eta),
		strings.Repeat("─", 60),
	}
}

func fmtDur(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	s := int((d % time.Minute) / time.Second)
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func (e *Engine) recordItemError(kind string, it artifactory.Item, err error) {
	e.stat.errors.Add(1)
	e.errMu.Lock()
	e.errs = append(e.errs, ScanError{
		Repo: it.Repo, Path: it.Path, Name: it.Name, Sha256: it.Sha256, Size: it.Size,
		Kind: kind, Error: err.Error(), Ts: time.Now().UTC().Format(time.RFC3339),
	})
	e.errMu.Unlock()
}

func (e *Engine) recordRepoError(r artifactory.Repo, err error) {
	e.stat.errors.Add(1)
	e.errMu.Lock()
	e.errs = append(e.errs, ScanError{
		Repo: r.Key, Kind: "repo", Type: r.Type, PackageType: r.PackageType,
		Error: err.Error(), Ts: time.Now().UTC().Format(time.RFC3339),
	})
	e.errMu.Unlock()
}

// ScanErrors returns a copy of the per-item/per-repo failures collected this run.
func (e *Engine) ScanErrors() []ScanError {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	out := make([]ScanError, len(e.errs))
	copy(out, e.errs)
	return out
}

func (e *Engine) statsSnapshot(start time.Time, repos int) Stats {
	d := time.Since(start)
	return Stats{
		ReposScanned:    repos,
		FilesScanned:    int(e.stat.filesScanned.Load()),
		FilesSkipped:    int(e.stat.filesSkipped.Load()),
		BytesDownloaded: e.stat.bytesDownloaded.Load(),
		Findings:        int(e.stat.findings.Load()),
		Errors:          int(e.stat.errors.Load()),
		Duration:        d.Round(time.Second).String(),
	}
}

// list enumerates and pre-filters files across repos.
func (e *Engine) list(ctx context.Context, repos []artifactory.Repo) []artifactory.Item {
	var items []artifactory.Item
	var listed int
	for i, r := range repos {
		if ctx.Err() != nil {
			break
		}
		before := len(items)
		emit := func(it artifactory.Item) error {
			listed++
			scan, isArch := e.sel.classify(it.Name)
			if !scan {
				return nil
			}
			if e.cfg.MaxFileSize > 0 && it.Size > e.cfg.MaxFileSize && !isArch {
				return nil
			}
			items = append(items, it)
			return nil
		}
		// For REMOTE repos, list/download the cached copy ("<key>-cache") so we
		// never trigger an upstream fetch through the proxy (noisy + leaks intent).
		listKey := r.Key
		if strings.EqualFold(r.Type, "REMOTE") {
			listKey = r.Key + "-cache"
		}
		err := e.c.ListItemsAQL(ctx, listKey, e.cfg.PageSize, e.cfg.ModifiedSince, emit)
		if err != nil {
			if errors.Is(err, artifactory.ErrForbidden) {
				if e.cfg.Verbose {
					fmt.Fprintf(os.Stderr, "[i] AQL denied for %s, falling back to Storage API\n", listKey)
				}
				if !e.cfg.ModifiedSince.IsZero() {
					fmt.Fprintf(os.Stderr, "[!] --since needs AQL; Storage-API fallback for %s cannot filter by date (all items listed)\n", listKey)
				}
				// Discard any partial AQL output so the fallback doesn't duplicate.
				items = items[:before]
				if ferr := e.c.ListItemsStorage(ctx, listKey, emit); ferr != nil {
					fmt.Fprintf(os.Stderr, "[!] list %s failed: %v\n", listKey, ferr)
					e.recordRepoError(r, ferr)
					continue
				}
			} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				break
			} else {
				fmt.Fprintf(os.Stderr, "[!] list %s failed: %v\n", listKey, err)
				e.recordRepoError(r, err)
				continue
			}
		}
		// Live repo counter during the (otherwise silent) listing phase.
		fmt.Fprintf(os.Stderr, "[i] listing repos %d/%d · %s: %d selected (%d total)\n",
			i+1, len(repos), r.Key, len(items)-before, len(items))
	}
	return items
}

// scanItem downloads and scans a single artifact.
func (e *Engine) scanItem(ctx context.Context, it artifactory.Item) {
	e.stat.filesProcessed.Add(1)
	defer e.markRepoDone(it.Repo)
	key := resumeKey(it)
	if e.cfg.ResumePath != "" {
		e.resumeMu.Lock()
		seen := e.resumeSeen[key]
		e.resumeMu.Unlock()
		if seen {
			e.stat.filesSkipped.Add(1)
			return
		}
	}

	dlCap := e.cfg.MaxFileSize
	_, isArch := e.sel.classify(it.Name)
	if isArch && dlCap > 0 {
		dlCap = dlCap * 8 // allow larger archives; entries are still bounded
	}
	// A re-tried Docker blob (named sha256__<hex>) may be a big layer: give it the
	// layer budget so it isn't truncated.
	isDockerBlob := strings.HasPrefix(strings.ToLower(it.Name), "sha256__")
	if isDockerBlob && e.cfg.MaxLayerSize > dlCap {
		dlCap = e.cfg.MaxLayerSize
	}
	data, err := e.c.Download(ctx, it, dlCap)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			if e.cfg.Verbose {
				fmt.Fprintf(os.Stderr, "[!] download %s/%s: %v\n", it.Repo, it.FullPath(), err)
			}
			e.recordItemError("item", it, err)
		}
		return
	}
	e.stat.bytesDownloaded.Add(int64(len(data)))

	var fs []Finding
	if isArch {
		e.stat.filesScanned.Add(1)
		fs = e.scanArchive(it, data)
	} else if isBinary(data) {
		// A retried Docker layer blob is a gzip/tar filesystem — crack it; any
		// other binary is skipped.
		if isDockerBlob {
			e.stat.filesScanned.Add(1)
			fs = e.scanLayerBytes(it, data)
		} else {
			e.stat.filesSkipped.Add(1)
		}
	} else {
		e.stat.filesScanned.Add(1)
		fs = e.scanBlob(data)
	}
	e.addFindings(it, fs)

	// T2: when this is a Docker image manifest, also pull and scan the small
	// image config blob (ENV vars / build-args / labels live there in clear).
	if e.cfg.dockerActive() && isDockerManifest(it.Name) && e.isDockerRepo(it.Repo) {
		e.scanDockerImage(ctx, it, data)
	}
	e.markResume(key)
}

// scanBlob runs detectors (and the base64 pass) on text content.
func (e *Engine) scanBlob(content []byte) []Finding {
	li := newLineIndex(content)
	out := matchRules(e.rules, content, li, "")
	if e.cfg.DecodeBase64 {
		out = append(out, e.scanBase64(content, li)...)
	}
	return out
}

// scanLayerBytes scans a Docker image layer blob (gzip+tar, falling back to raw
// tar) for secrets. Shared by the live layer pass and --retry of layer blobs.
func (e *Engine) scanLayerBytes(it artifactory.Item, data []byte) []Finding {
	var reader io.Reader = bytes.NewReader(data)
	if gz, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
		defer gz.Close()
		reader = gz
	}
	return e.scanTar(it, reader)
}

// scanArchive opens common containers one level deep and scans text entries.
func (e *Engine) scanArchive(it artifactory.Item, data []byte) []Finding {
	name := strings.ToLower(it.Name)
	switch {
	case strings.HasSuffix(name, ".tar"):
		return e.scanTar(it, bytes.NewReader(data))
	case strings.HasSuffix(name, ".tgz"), strings.HasSuffix(name, ".tar.gz"):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			e.archiveErr(it, err)
			return nil
		}
		defer gz.Close()
		return e.scanTar(it, gz)
	case strings.HasSuffix(name, ".gz"):
		// Plain gzip of a single file (e.g. config.json.gz), not a tarball.
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			e.archiveErr(it, err)
			return nil
		}
		defer gz.Close()
		dec, _ := io.ReadAll(io.LimitReader(gz, archiveEntryCap(e.cfg.MaxFileSize)))
		if isBinary(dec) {
			return nil
		}
		inner := it.FullPath() + "!" + strings.TrimSuffix(it.Name, ".gz")
		var out []Finding
		for _, fnd := range e.scanBlob(dec) {
			fnd.Path = inner
			out = append(out, fnd)
		}
		return out
	default: // zip-family: jar/war/ear/zip/nupkg/whl/egg/aar/apk/crate
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			e.archiveErr(it, err)
			return nil
		}
		return e.scanZip(it, zr)
	}
}

func (e *Engine) archiveErr(it artifactory.Item, err error) {
	e.recordItemError("archive", it, err)
	if e.cfg.Verbose {
		fmt.Fprintf(os.Stderr, "[!] open archive %s/%s: %v\n", it.Repo, it.FullPath(), err)
	}
}

func (e *Engine) scanZip(it artifactory.Item, zr *zip.Reader) []Finding {
	var out []Finding
	var total int64
	budget := archiveBudget(e.cfg.MaxFileSize)
	entries := 0
	for _, f := range zr.File {
		if entries >= maxArchiveEntries || total >= budget {
			break // decompression-bomb guard: too many entries or too much output
		}
		if f.FileInfo().IsDir() {
			continue
		}
		entries++
		if !e.sel.classifyEntry(f.Name) {
			continue
		}
		if e.cfg.MaxFileSize > 0 && int64(f.UncompressedSize64) > e.cfg.MaxFileSize {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, archiveEntryCap(e.cfg.MaxFileSize)))
		rc.Close()
		total += int64(len(data))
		if isBinary(data) {
			continue
		}
		inner := it.FullPath() + "!" + f.Name
		for _, fnd := range e.scanBlob(data) {
			fnd.Path = inner
			out = append(out, fnd)
		}
	}
	return out
}

func (e *Engine) scanTar(it artifactory.Item, r io.Reader) []Finding {
	var out []Finding
	var total int64
	budget := archiveBudget(e.cfg.MaxFileSize)
	entries := 0
	tr := tar.NewReader(r)
	for {
		if entries >= maxArchiveEntries || total >= budget {
			break // decompression-bomb guard
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		entries++
		if !e.sel.classifyEntry(h.Name) {
			continue
		}
		if e.cfg.MaxFileSize > 0 && h.Size > e.cfg.MaxFileSize {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(tr, archiveEntryCap(e.cfg.MaxFileSize)))
		total += int64(len(data))
		if isBinary(data) {
			continue
		}
		inner := it.FullPath() + "!" + h.Name
		for _, fnd := range e.scanBlob(data) {
			fnd.Path = inner
			out = append(out, fnd)
		}
	}
	return out
}

const maxArchiveEntries = 20000

// archiveBudget caps total decompressed bytes scanned per archive.
func archiveBudget(maxFile int64) int64 {
	if maxFile <= 0 {
		return 512 << 20
	}
	b := maxFile * 64
	if b < 256<<20 {
		b = 256 << 20
	}
	if b > 1<<30 {
		b = 1 << 30
	}
	return b
}

// scanBase64 decodes long base64 runs and scans the decoded text, attributing
// any finding to the run's location in the original file.
func (e *Engine) scanBase64(content []byte, li *lineIndex) []Finding {
	var out []Finding
	seen := make(map[int]bool)
	// Two alphabets (standard +/ and URL-safe -_) scanned separately so a run
	// is captured cleanly in its own alphabet rather than as a mixed, undecodable
	// blob.
	for _, re := range base64Regexes {
		for _, m := range re.FindAllIndex(content, 256) {
			if seen[m[0]] {
				continue
			}
			runLen := m[1] - m[0]
			if runLen < 24 || runLen > 256*1024 {
				continue
			}
			dec := decodeBase64(content[m[0]:m[1]])
			if len(dec) < 8 || !utf8.Valid(dec) || !mostlyPrintable(dec) {
				continue
			}
			sub := matchRules(e.rules, dec, newLineIndex(dec), "base64")
			if len(sub) == 0 {
				continue
			}
			seen[m[0]] = true
			line, col := li.at(m[0])
			for _, f := range sub {
				f.Line, f.Column = line, col
				out = append(out, f)
			}
		}
	}
	return out
}

// addFindings stores findings for an item. Secrets are kept raw here (and the
// Match is the un-redacted context); redaction happens once in finalizeFindings
// after cross-rule dedup, so the dedup key can use the real secret value.
func (e *Engine) addFindings(it artifactory.Item, fs []Finding) {
	if len(fs) == 0 {
		return
	}
	minRank := SeverityRank(e.cfg.MinSeverity)
	fileURL := e.c.ArtifactURL(it.Repo, it.FullPath())

	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range fs {
		f := fs[i]
		if e.cfg.MinSeverity != "" && SeverityRank(f.Severity) < minRank {
			continue
		}
		if f.Path == "" || !strings.Contains(f.Path, "!") {
			f.Path = it.FullPath()
		}
		f.Fingerprint = fingerprint(f.RuleID, it.Repo, f.Path, f.Secret)
		if e.seenFP[f.Fingerprint] {
			continue // exact same rule+location+secret already recorded
		}
		e.seenFP[f.Fingerprint] = true
		f.Repo = it.Repo
		f.FileURL = fileURL
		f.Size = it.Size
		f.Sha256 = it.Sha256
		e.findings = append(e.findings, f)
		e.stat.findings.Add(1)
		e.bumpSev(f.Severity)
		if e.cfg.Live {
			line := liveLine(f, e.cfg.ShowSecrets)
			if e.dash != nil {
				e.dash.addLine(line)
			} else {
				fmt.Fprintln(os.Stderr, line)
			}
		}
	}
}

// liveLine formats a finding for the live view (redacted unless ShowSecrets).
func liveLine(f Finding, show bool) string {
	val := redactValue(f.Secret, f.Entropy)
	if show {
		val = f.Secret
	}
	via := ""
	if f.ViaDecoder != "" {
		via = " (via " + f.ViaDecoder + ")"
	}
	return fmt.Sprintf("[+] %-8s %-22s %s/%s:%d  %s%s",
		strings.ToUpper(f.Severity), f.RuleID, f.Repo, f.Path, f.Line, val, via)
}

func (e *Engine) bumpSev(sev string) {
	switch strings.ToLower(sev) {
	case "critical":
		e.stat.sevCrit.Add(1)
	case "high":
		e.stat.sevHigh.Add(1)
	case "medium":
		e.stat.sevMed.Add(1)
	case "low":
		e.stat.sevLow.Add(1)
	}
}

// dedupeBySecret collapses different rules that matched the SAME secret value at
// the same location into one finding, preferring the most specific (non-generic,
// highest-severity) detector. Prevents e.g. a Stripe key being reported by both
// stripe-secret and generic-secret-assign.
func dedupeBySecret(fs []Finding) []Finding {
	type keyT struct {
		repo, path, secret string
		line               int
	}
	best := make(map[keyT]int) // key -> index into out
	var out []Finding
	for _, f := range fs {
		if f.Secret == "" { // no comparable value; keep as-is
			out = append(out, f)
			continue
		}
		k := keyT{f.Repo, f.Path, f.Secret, f.Line}
		if idx, ok := best[k]; ok {
			if moreSpecific(f, out[idx]) {
				out[idx] = f
			}
			continue
		}
		best[k] = len(out)
		out = append(out, f)
	}
	return out
}

// moreSpecific reports whether a should win over b for the same secret.
// Severity is compared FIRST so dedup can never downgrade a finding; the
// specific-over-generic preference only breaks ties at equal severity.
func moreSpecific(a, b Finding) bool {
	ra, rb := SeverityRank(a.Severity), SeverityRank(b.Severity)
	if ra != rb {
		return ra > rb
	}
	ag, bg := isGenericRule(a), isGenericRule(b)
	if ag != bg {
		return !ag
	}
	return false
}

func isGenericRule(f Finding) bool {
	return f.Category == "generic" || strings.HasPrefix(f.RuleID, "generic")
}

// finalizeFindings applies redaction in place unless --show-secrets is set.
func (e *Engine) finalizeFindings(fs []Finding) {
	for i := range fs {
		if e.cfg.ShowSecrets {
			continue // keep full Match and Secret
		}
		// Replace the context Match with a redaction of the SECRET value only, so
		// no surrounding plaintext (or secret head/tail) leaks by default.
		fs[i].Match = redactValue(fs[i].Secret, fs[i].Entropy)
		fs[i].Secret = ""
	}
}

// --- resume / checkpoint ---

func (e *Engine) loadResume() error {
	if e.cfg.ResumePath == "" {
		return nil
	}
	if data, err := os.ReadFile(e.cfg.ResumePath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				e.resumeSeen[line] = true
			}
		}
		fmt.Fprintf(os.Stderr, "[i] resume: %d already-scanned file(s) will be skipped\n", len(e.resumeSeen))
	}
	f, err := os.OpenFile(e.cfg.ResumePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open resume file: %w", err)
	}
	e.resumeFile = f
	return nil
}

func (e *Engine) markResume(key string) {
	if e.cfg.ResumePath == "" || e.resumeFile == nil {
		return
	}
	e.resumeMu.Lock()
	defer e.resumeMu.Unlock()
	if e.resumeSeen[key] {
		return
	}
	e.resumeSeen[key] = true
	fmt.Fprintln(e.resumeFile, key)
}

func (e *Engine) closeResume() {
	if e.resumeFile != nil {
		e.resumeFile.Close()
	}
}

func resumeKey(it artifactory.Item) string {
	if it.Sha256 != "" {
		return it.Repo + "|" + it.FullPath() + "|" + it.Sha256
	}
	return it.Repo + "|" + it.FullPath()
}

// --- content heuristics ---

// isBinary reports whether data looks non-textual (NUL byte or many controls).
func isBinary(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	n := len(data)
	if n > 8192 {
		n = 8192
	}
	sample := data[:n]
	if bytes.IndexByte(sample, 0) >= 0 {
		return true
	}
	var nonText int
	for _, b := range sample {
		if b == '\n' || b == '\r' || b == '\t' || b == '\f' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			nonText++
		}
	}
	return float64(nonText)/float64(n) > 0.30
}

func mostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	var printable int
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || (b >= 0x20 && b < 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.85
}

func archiveEntryCap(maxFile int64) int64 {
	if maxFile <= 0 {
		return 16 << 20
	}
	return maxFile
}

func sortFindings(fs []Finding) {
	// Sort by severity desc, then repo, then path, then line.
	sort.SliceStable(fs, func(i, j int) bool { return lessFinding(fs[i], fs[j]) })
}

func lessFinding(a, b Finding) bool {
	ra, rb := SeverityRank(a.Severity), SeverityRank(b.Severity)
	if ra != rb {
		return ra > rb
	}
	if a.Repo != b.Repo {
		return a.Repo < b.Repo
	}
	if a.Path != b.Path {
		return a.Path < b.Path
	}
	return a.Line < b.Line
}
