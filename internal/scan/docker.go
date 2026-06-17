package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/0x3EB/arthunt/internal/artifactory"
)

// T2 (Docker, config-only) scans the small image CONFIG blob referenced by a
// manifest — where ENV vars, build-args and labels live in clear — and never
// fetches the heavy layer blobs (that is T3).
//
// For a multi-arch tag, each per-platform manifest is stored as its own
// manifest.json elsewhere in the repo, so it is listed and scanned independently
// by the normal walk. We therefore do NOT chase a manifest list's sub-manifest
// digests: their on-disk path is not in the tag folder, and the listing already
// covers them (chasing them would only 404 and add OPSEC noise).

const dockerBlobCap = 4 << 20 // config blobs are tiny; cap generously

// dockerManifest decodes a schema-2 / OCI image manifest: the config blob digest
// and, for T3, the layer blob digests + sizes. (A manifest list has no config.)
type dockerManifest struct {
	Config struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	} `json:"layers"`
}

func isDockerManifest(name string) bool {
	n := strings.ToLower(name)
	return n == "manifest.json" || n == "list.manifest.json"
}

func (e *Engine) isDockerRepo(repo string) bool {
	if len(e.dockerRepos) == 0 {
		return true // packageType unknown — a manifest.json is signal enough
	}
	return e.dockerRepos[repo]
}

// blobName maps a registry digest ("sha256:HEX") to Artifactory's on-disk blob
// filename ("sha256__HEX").
func blobName(digest string) string {
	return strings.Replace(strings.TrimSpace(digest), ":", "__", 1)
}

// scanDockerImage scans the image config blob referenced by a manifest (already
// downloaded as data). The config sits beside the manifest as sha256__<hex>.
func (e *Engine) scanDockerImage(ctx context.Context, manifestItem artifactory.Item, data []byte) {
	if ctx.Err() != nil {
		return
	}
	var m dockerManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return // manifest list / unparseable — nothing extra to fetch
	}
	if m.Config.Digest != "" {
		e.fetchDockerConfig(ctx, manifestItem.Repo, manifestItem.Path, m.Config.Digest,
			manifestItem.FullPath()+"!config:"+shortDigest(m.Config.Digest))
	}
	// T3: also crack the image layers (filesystem diffs) for baked-in secrets.
	if e.cfg.DockerLayers {
		for _, lyr := range m.Layers {
			if ctx.Err() != nil {
				return
			}
			if e.cfg.MaxLayerSize > 0 && lyr.Size > e.cfg.MaxLayerSize {
				if e.cfg.Verbose {
					fmt.Fprintf(os.Stderr, "[i] skip layer %s (%d bytes > --max-layer-size)\n", shortDigest(lyr.Digest), lyr.Size)
				}
				continue
			}
			e.fetchDockerLayer(ctx, manifestItem.Repo, manifestItem.Path, lyr.Digest)
		}
	}
}

// fetchDockerLayer downloads an image layer blob once (cross-image digest dedup —
// shared base layers are fetched a single time), then scans its filesystem
// (gzip+tar, falling back to raw tar) for secrets. Per-entry size and total
// budget are bounded by scanTar.
func (e *Engine) fetchDockerLayer(ctx context.Context, repo, folder, digest string) {
	if digest == "" {
		return
	}
	e.dockerMu.Lock()
	seen := e.dockerSeen[digest]
	e.dockerMu.Unlock()
	if seen {
		return
	}

	blob := artifactory.Item{Repo: repo, Path: folder, Name: blobName(digest)}
	data, err := e.c.Download(ctx, blob, e.cfg.MaxLayerSize)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			if e.cfg.Verbose {
				fmt.Fprintf(os.Stderr, "[!] docker layer %s/%s: %v\n", repo, blob.FullPath(), err)
			}
			e.recordItemError("docker", blob, err)
		}
		return
	}
	e.dockerMu.Lock()
	e.dockerSeen[digest] = true
	e.dockerMu.Unlock()

	e.stat.bytesDownloaded.Add(int64(len(data)))
	e.stat.filesScanned.Add(1)

	layerItem := artifactory.Item{Repo: repo, Path: folder, Name: blobName(digest)}
	e.addFindings(layerItem, e.scanLayerBytes(layerItem, data))
}

// fetchDockerConfig downloads a config blob once (cross-image digest dedup) and
// scans it. The digest is recorded as seen only AFTER a successful fetch, so a
// transient error never permanently suppresses that config for other images.
func (e *Engine) fetchDockerConfig(ctx context.Context, repo, folder, digest, label string) {
	if digest == "" {
		return
	}
	e.dockerMu.Lock()
	seen := e.dockerSeen[digest]
	e.dockerMu.Unlock()
	if seen {
		return
	}

	blob := artifactory.Item{Repo: repo, Path: folder, Name: blobName(digest)}
	data, err := e.c.Download(ctx, blob, dockerBlobCap)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			if e.cfg.Verbose {
				fmt.Fprintf(os.Stderr, "[!] docker config %s/%s: %v\n", repo, blob.FullPath(), err)
			}
			e.recordItemError("docker", blob, err)
		}
		return // not marked seen — a later image may legitimately retry this digest
	}
	e.dockerMu.Lock()
	e.dockerSeen[digest] = true
	e.dockerMu.Unlock()

	e.stat.bytesDownloaded.Add(int64(len(data)))
	if isBinary(data) {
		return // a layer/binary blob slipped through — not a config
	}
	e.stat.filesScanned.Add(1)
	blob.Size = int64(len(data))
	var fs []Finding
	for _, f := range e.scanBlob(data) {
		f.Path = label
		fs = append(fs, f)
	}
	e.addFindings(blob, fs)
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(strings.TrimSpace(d), "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}
