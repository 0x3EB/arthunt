// Package report renders scan findings to JSON, CSV and a self-contained,
// offline HTML report (no external resources — safe to open air-gapped).
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0x3EB/arthunt/internal/scan"
)

// Meta describes the scan run for the report header.
type Meta struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	Target      string    `json:"target"`
	RulesetVer  string    `json:"ruleset_version"`
	RuleCount   int       `json:"rule_count"`
	GeneratedAt time.Time `json:"generated_at"`
	Profile     string    `json:"profile"`
}

// Report bundles everything for serialization.
type Report struct {
	Meta     Meta           `json:"meta"`
	Stats    scan.Stats     `json:"stats"`
	Findings []scan.Finding `json:"findings"`
}

// createSecure creates/truncates a file readable only by the owner (0600);
// reports can contain cleartext secrets with --show-secrets.
func createSecure(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
}

// WriteJSON writes the full report as indented JSON.
func WriteJSON(path string, r Report) error {
	f, err := createSecure(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// WriteErrorsJSONL writes one JSON object per failed item/repo (0600), so the
// run's errors are both human-readable and replayable via --retry.
func WriteErrorsJSONL(path string, errs []scan.ScanError) error {
	f, err := createSecure(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for i := range errs {
		if err := enc.Encode(errs[i]); err != nil {
			return err
		}
	}
	return nil
}

// LoadErrorsJSONL reads a previously written errors file (used by --retry).
func LoadErrorsJSONL(path string) ([]scan.ScanError, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []scan.ScanError
	dec := json.NewDecoder(f)
	for dec.More() {
		var e scan.ScanError
		if err := dec.Decode(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// LoadJSON reads a previously written JSON report (used by --merge).
func LoadJSON(path string) (Report, error) {
	var r Report
	data, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, fmt.Errorf("parse %s: %w", path, err)
	}
	return r, nil
}

// WriteCSV writes findings as CSV.
func WriteCSV(path string, r Report) error {
	f, err := createSecure(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"severity", "rule", "category", "repo", "path", "line", "column", "match", "secret", "entropy", "via_decoder", "file_url", "fingerprint"})
	for _, fd := range r.Findings {
		_ = w.Write([]string{
			csvSafe(fd.Severity), csvSafe(fd.RuleName), csvSafe(fd.Category), csvSafe(fd.Repo), csvSafe(fd.Path),
			strconv.Itoa(fd.Line), strconv.Itoa(fd.Column), csvSafe(fd.Match), csvSafe(fd.Secret),
			strconv.FormatFloat(fd.Entropy, 'f', 2, 64), csvSafe(fd.ViaDecoder), csvSafe(fd.FileURL), fd.Fingerprint,
		})
	}
	return w.Error()
}

// csvSafe neutralises spreadsheet formula injection: a cell whose value starts
// with =, +, -, @ (or a control char) is executed as a formula by Excel/Sheets.
// Target-controlled values (repo/path/match/secret) are prefixed with a quote.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// counts aggregates findings for the summary panels.
func counts(fs []scan.Finding) (bySev map[string]int, byCat map[string]int, byRepo map[string]int) {
	bySev, byCat, byRepo = map[string]int{}, map[string]int{}, map[string]int{}
	for _, f := range fs {
		bySev[f.Severity]++
		byCat[f.Category]++
		byRepo[f.Repo]++
	}
	return
}

func sortedKeysByVal(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

// WriteHTML renders a self-contained interactive report.
func WriteHTML(path string, r Report) error {
	f, err := createSecure(path)
	if err != nil {
		return err
	}
	defer f.Close()

	bySev, byCat, byRepo := counts(r.Findings)
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString("<title>arthunt report — ")
	b.WriteString(html.EscapeString(r.Meta.Target))
	b.WriteString("</title>")
	b.WriteString("<style>" + cssBlock + "</style></head><body>")

	// Header
	b.WriteString(`<header><h1>arthunt</h1><div class="sub">Artifactory secret audit</div></header>`)
	b.WriteString(`<section class="meta">`)
	metaRow(&b, "Target", r.Meta.Target)
	metaRow(&b, "Generated", r.Meta.GeneratedAt.Format(time.RFC1123))
	metaRow(&b, "Profile", r.Meta.Profile)
	metaRow(&b, "Detectors", strconv.Itoa(r.Meta.RuleCount)+" (ruleset "+r.Meta.RulesetVer+")")
	metaRow(&b, "Repos scanned", strconv.Itoa(r.Stats.ReposScanned))
	metaRow(&b, "Files scanned", strconv.Itoa(r.Stats.FilesScanned)+" / "+strconv.Itoa(r.Stats.FilesSelected)+" selected")
	metaRow(&b, "Downloaded", humanBytes(r.Stats.BytesDownloaded))
	metaRow(&b, "Duration", r.Stats.Duration)
	metaRow(&b, "Errors", strconv.Itoa(r.Stats.Errors))
	b.WriteString(`</section>`)

	// Summary cards
	b.WriteString(`<section class="cards">`)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		b.WriteString(fmt.Sprintf(`<div class="card sev-%s"><div class="num">%d</div><div class="lbl">%s</div></div>`,
			sev, bySev[sev], sev))
	}
	b.WriteString(fmt.Sprintf(`<div class="card total"><div class="num">%d</div><div class="lbl">total</div></div>`, len(r.Findings)))
	b.WriteString(`</section>`)

	// Breakdown
	b.WriteString(`<section class="breakdown">`)
	breakdownList(&b, "By repository", byRepo)
	breakdownList(&b, "By category", byCat)
	b.WriteString(`</section>`)

	// Controls
	b.WriteString(`<section class="controls">`)
	b.WriteString(`<input id="q" type="search" placeholder="filter (rule, repo, path, match)…">`)
	b.WriteString(`<select id="sev"><option value="">all severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select>`)
	b.WriteString(`<span id="shown"></span>`)
	b.WriteString(`</section>`)

	// Table
	b.WriteString(`<table id="t"><thead><tr>`)
	for _, h := range []string{"Severity", "Rule", "Repo", "Path", "Line", "Match", "Entropy", "Via"} {
		b.WriteString("<th>" + h + "</th>")
	}
	b.WriteString(`</tr></thead><tbody>`)
	for _, fd := range r.Findings {
		hay := strings.ToLower(fd.RuleName + " " + fd.Repo + " " + fd.Path + " " + fd.Match + " " + fd.Category)
		sev := html.EscapeString(fd.Severity)
		b.WriteString(`<tr data-sev="` + sev + `" data-h="` + html.EscapeString(hay) + `">`)
		b.WriteString(`<td><span class="badge sev-` + sev + `">` + sev + `</span></td>`)
		b.WriteString(`<td>` + html.EscapeString(fd.RuleName) + `</td>`)
		b.WriteString(`<td>` + html.EscapeString(fd.Repo) + `</td>`)
		path := fd.Path
		if fd.FileURL != "" {
			b.WriteString(`<td><a href="` + html.EscapeString(fd.FileURL) + `" target="_blank" rel="noreferrer">` + html.EscapeString(path) + `</a></td>`)
		} else {
			b.WriteString(`<td>` + html.EscapeString(path) + `</td>`)
		}
		b.WriteString(`<td>` + strconv.Itoa(fd.Line) + `</td>`)
		b.WriteString(`<td class="match"><code>` + html.EscapeString(fd.Match) + `</code></td>`)
		b.WriteString(`<td>` + strconv.FormatFloat(fd.Entropy, 'f', 2, 64) + `</td>`)
		b.WriteString(`<td>` + html.EscapeString(fd.ViaDecoder) + `</td>`)
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table>`)
	b.WriteString(`<footer>Generated by arthunt ` + html.EscapeString(r.Meta.Version) + ` — passive detection, values redacted unless --show-secrets.</footer>`)
	b.WriteString("<script>" + jsBlock + "</script>")
	b.WriteString("</body></html>")

	_, err = f.WriteString(b.String())
	return err
}

func metaRow(b *strings.Builder, k, v string) {
	if v == "" {
		v = "—"
	}
	b.WriteString(`<div class="mrow"><span class="k">` + html.EscapeString(k) + `</span><span class="v">` + html.EscapeString(v) + `</span></div>`)
}

func breakdownList(b *strings.Builder, title string, m map[string]int) {
	b.WriteString(`<div class="bd"><h3>` + html.EscapeString(title) + `</h3><ul>`)
	keys := sortedKeysByVal(m)
	for i, k := range keys {
		if i >= 25 {
			b.WriteString(`<li class="more">… ` + strconv.Itoa(len(keys)-25) + ` more</li>`)
			break
		}
		label := k
		if label == "" {
			label = "(uncategorised)"
		}
		b.WriteString(`<li><span class="bk">` + html.EscapeString(label) + `</span><span class="bv">` + strconv.Itoa(m[k]) + `</span></li>`)
	}
	b.WriteString(`</ul></div>`)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

const cssBlock = `
:root{--bg:#0f1115;--panel:#171a21;--line:#262b36;--fg:#e6e9ef;--mut:#9aa3b2;
--crit:#ff4d4f;--high:#ff8c00;--med:#e6c200;--low:#3fa7ff;--accent:#5ee0a0;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:20px 28px;border-bottom:1px solid var(--line);display:flex;align-items:baseline;gap:14px}
header h1{margin:0;font-size:22px;letter-spacing:.5px;color:var(--accent)}
header .sub{color:var(--mut)}
section{padding:18px 28px;border-bottom:1px solid var(--line)}
.meta{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:6px 26px}
.mrow{display:flex;justify-content:space-between;border-bottom:1px dotted var(--line);padding:3px 0}
.mrow .k{color:var(--mut)}.mrow .v{font-weight:600;text-align:right;word-break:break-all}
.cards{display:flex;gap:14px;flex-wrap:wrap}
.card{flex:1;min-width:120px;background:var(--panel);border:1px solid var(--line);
border-radius:10px;padding:16px;text-align:center}
.card .num{font-size:30px;font-weight:700}.card .lbl{color:var(--mut);text-transform:uppercase;font-size:11px;letter-spacing:1px}
.card.sev-critical .num{color:var(--crit)}.card.sev-high .num{color:var(--high)}
.card.sev-medium .num{color:var(--med)}.card.sev-low .num{color:var(--low)}
.card.total .num{color:var(--accent)}
.breakdown{display:flex;gap:28px;flex-wrap:wrap}
.bd{flex:1;min-width:280px}.bd h3{margin:0 0 8px;font-size:13px;color:var(--mut);text-transform:uppercase;letter-spacing:1px}
.bd ul{list-style:none;margin:0;padding:0}.bd li{display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px dotted var(--line)}
.bd .bv{font-weight:700;color:var(--accent)}.bd .more{color:var(--mut)}
.controls{display:flex;gap:12px;align-items:center;flex-wrap:wrap;position:sticky;top:0;background:var(--bg);z-index:5}
#q{flex:1;min-width:240px;background:var(--panel);border:1px solid var(--line);color:var(--fg);padding:9px 12px;border-radius:8px}
#sev{background:var(--panel);border:1px solid var(--line);color:var(--fg);padding:9px;border-radius:8px}
#shown{color:var(--mut)}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{position:sticky;top:54px;background:var(--panel);text-align:left;padding:9px 12px;border-bottom:2px solid var(--line);cursor:pointer;user-select:none}
tbody td{padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:hover{background:#1c212b}
.match code{background:#0a0c10;border:1px solid var(--line);border-radius:6px;padding:2px 6px;color:#ffd479;word-break:break-all}
a{color:var(--low);text-decoration:none}a:hover{text-decoration:underline}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase}
.badge.sev-critical{background:rgba(255,77,79,.18);color:var(--crit);border:1px solid var(--crit)}
.badge.sev-high{background:rgba(255,140,0,.16);color:var(--high);border:1px solid var(--high)}
.badge.sev-medium{background:rgba(230,194,0,.14);color:var(--med);border:1px solid var(--med)}
.badge.sev-low{background:rgba(63,167,255,.14);color:var(--low);border:1px solid var(--low)}
footer{padding:18px 28px;color:var(--mut)}
`

const jsBlock = `
(function(){
 var q=document.getElementById('q'),sev=document.getElementById('sev'),
 shown=document.getElementById('shown'),tb=document.querySelector('#t tbody'),
 rows=[].slice.call(tb.querySelectorAll('tr'));
 function apply(){var term=q.value.toLowerCase().trim(),s=sev.value,n=0;
  rows.forEach(function(r){var ok=(!s||r.dataset.sev===s)&&(!term||r.dataset.h.indexOf(term)>=0);
   r.style.display=ok?'':'none';if(ok)n++;});
  shown.textContent=n+' / '+rows.length+' shown';}
 q.addEventListener('input',apply);sev.addEventListener('change',apply);
 var rank={critical:4,high:3,medium:2,low:1};
 document.querySelectorAll('#t thead th').forEach(function(th,idx){
  var asc=true;th.addEventListener('click',function(){
   rows.sort(function(a,b){var x=a.children[idx].innerText.trim(),y=b.children[idx].innerText.trim();
    if(idx===0){x=rank[a.dataset.sev]||0;y=rank[b.dataset.sev]||0;}
    else if(idx===4){x=parseInt(x)||0;y=parseInt(y)||0;}
    else if(idx===6){x=parseFloat(x)||0;y=parseFloat(y)||0;}
    return (x<y?-1:x>y?1:0)*(asc?1:-1);});
   asc=!asc;rows.forEach(function(r){tb.appendChild(r);});});});
 apply();
})();
`
