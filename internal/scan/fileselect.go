package scan

import (
	"path"
	"strings"
)

// textExtensions are file types worth scanning in "text/config only" mode.
var textExtensions = map[string]bool{
	".txt": true, ".text": true, ".md": true, ".markdown": true, ".rst": true,
	".properties": true, ".prop": true, ".props": true, ".env": true,
	".cfg": true, ".conf": true, ".config": true, ".ini": true, ".toml": true,
	".yaml": true, ".yml": true, ".json": true, ".json5": true, ".jsonc": true,
	".xml": true, ".plist": true, ".csv": true, ".tsv": true,
	".gradle": true, ".sbt": true, ".pom": true, ".lock": true,
	".npmrc": true, ".yarnrc": true, ".pypirc": true, ".netrc": true,
	".pem": true, ".key": true, ".crt": true, ".cer": true, ".pub": true,
	".ppk": true, ".asc": true, ".gpg": true, ".kbx": true,
	".sql": true, ".sh": true, ".bash": true, ".zsh": true, ".ksh": true,
	".ps1": true, ".psm1": true, ".psd1": true, ".bat": true, ".cmd": true,
	".py": true, ".rb": true, ".pl": true, ".pm": true, ".php": true,
	".js": true, ".cjs": true, ".mjs": true, ".ts": true, ".jsx": true, ".tsx": true,
	".go": true, ".java": true, ".kt": true, ".kts": true, ".scala": true, ".clj": true,
	".groovy": true, ".gvy": true, ".cs": true, ".vb": true, ".fs": true,
	".c": true, ".h": true, ".cpp": true, ".hpp": true, ".cc": true,
	".rs": true, ".swift": true, ".dart": true, ".lua": true, ".r": true,
	".tf": true, ".tfvars": true, ".hcl": true, ".nomad": true,
	".dockerfile": true, ".dockercfg": true, ".dockerignore": true,
	".htpasswd": true, ".htaccess": true, ".pp": true, ".erb": true,
	".j2": true, ".jinja": true, ".tpl": true, ".template": true, ".tmpl": true,
	".cnf": true, ".cf": true, ".service": true, ".desktop": true, ".reg": true,
	".gitconfig": true, ".credentials": true, ".secret": true, ".secrets": true,
	".vault": true, ".cred": true, ".pwd": true, ".pass": true, ".tpr": true,
}

// specialNames are filenames worth scanning regardless of (missing) extension.
var specialNames = map[string]bool{
	"dockerfile": true, "containerfile": true, ".npmrc": true, ".yarnrc": true,
	".yarnrc.yml": true, ".pypirc": true, ".netrc": true, "_netrc": true,
	".git-credentials": true, ".gitconfig": true, "credentials": true,
	"config": true, ".env": true, ".env.local": true, ".env.prod": true,
	".env.production": true, ".env.dev": true, ".env.development": true,
	"settings.xml": true, "web.config": true, "app.config": true,
	"application.properties": true, "application.yml": true, "application.yaml": true,
	"docker-compose.yml": true, "docker-compose.yaml": true, "compose.yml": true,
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
	".htpasswd": true, ".dockercfg": true, "config.json": true, ".bash_history": true,
	".bashrc": true, ".bash_profile": true, ".zshrc": true, ".profile": true,
	"terraform.tfstate": true, "secrets.yml": true, "secrets.yaml": true,
	"vault.yml": true, "vault.yaml": true, ".s3cfg": true, ".boto": true,
	"hub": true, "wp-config.php": true, "local.settings.json": true,
}

// archiveExtensions are openable containers (one level) when --crack is set.
var archiveExtensions = map[string]bool{
	".jar": true, ".war": true, ".ear": true, ".zip": true, ".aar": true,
	".nupkg": true, ".whl": true, ".egg": true, ".gem": true, ".apk": true,
	".tgz": true, ".tar": true, ".gz": true, ".crate": true,
}

// alwaysSkipExt are large/binary types never worth fetching even in crack mode.
var alwaysSkipExt = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".bmp": true,
	".ico": true, ".webp": true, ".svg": true, ".mp3": true, ".mp4": true,
	".avi": true, ".mov": true, ".mkv": true, ".flac": true, ".wav": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true, ".iso": true, ".dmg": true, ".bin": true,
	".so": true, ".dll": true, ".dylib": true, ".class": true, ".o": true,
	".a": true, ".lib": true, ".obj": true, ".pyc": true, ".wasm": true,
	".node": true, ".db": true, ".sqlite": true, ".mo": true,
}

// selector decides which files to fetch and whether they are archives.
type selector struct {
	textOnly bool
	crack    bool
	extra    map[string]bool
	noFiles  bool // skip regular files; only targeted modes (docker) are selected
	docker   bool // a docker mode is active (config or layers)
}

func newSelector(textOnly, crack bool, extra []string) *selector {
	em := map[string]bool{}
	for _, e := range extra {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		em[e] = true
	}
	return &selector{textOnly: textOnly, crack: crack, extra: em}
}

// classify decides, for a TOP-LEVEL repo file, whether to fetch it and whether
// it is an archive to crack. Honours --no-files (listing-level scoping).
func (s *selector) classify(name string) (scan bool, isArchive bool) {
	base := strings.ToLower(path.Base(name))
	ext := strings.ToLower(path.Ext(base))

	// --no-files: skip everything except the Docker manifests needed to drive the
	// docker pass (config/layers are fetched from those, not from the file list).
	if s.noFiles {
		if s.docker && isDockerManifest(base) {
			return true, false
		}
		return false, false
	}

	if archiveExtensions[ext] {
		if s.crack {
			return true, true
		}
		return false, false
	}
	return s.textLike(base, ext), false
}

// classifyEntry decides whether an entry INSIDE an archive or Docker layer is a
// scannable text/config file. It ignores --no-files and archive/crack logic
// (we're already inside a targeted artifact and don't recurse nested archives).
func (s *selector) classifyEntry(name string) bool {
	base := strings.ToLower(path.Base(name))
	ext := strings.ToLower(path.Ext(base))
	return s.textLike(base, ext)
}

// textLike reports whether a filename looks like a scannable text/config file.
func (s *selector) textLike(base, ext string) bool {
	if alwaysSkipExt[ext] {
		return false
	}
	if s.extra[ext] {
		return true
	}
	if specialNames[base] {
		return true
	}
	if strings.HasPrefix(base, ".env") { // dotfiles like ".env.something"
		return true
	}
	if textExtensions[ext] {
		return true
	}
	if !s.textOnly && ext == "" { // permissive: extension-less config/scripts
		return true
	}
	return false
}
