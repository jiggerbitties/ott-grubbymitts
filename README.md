# OTT Stream Fingerprinter — Guide

`ott-fingerprint.py` is a single-file command-line tool. You point it at the
manifest URL of a streaming video (HLS `.m3u8` or DASH `.mpd`) and it reports
how much of the upstream **supply chain** can be inferred from the public
output alone: the CDN and origin, the packager, the codec and encoder, the DRM
system, the ABR ladder, and any ad-insertion / low-latency / trickplay
signalling.

It reads the same files a normal video player would and never bypasses DRM,
authentication, or geo controls. Use it only on streams you are authorised to
access, and respect each site's terms of service.

Hope this is useful team - jiggerbitties

---

## Quick start

The script lives **inside its folder** — by default:

    ~/Documents/ott-fingerprint/ott-fingerprint.py

Always call it by that **full path** (or `cd` into the folder first). Typing the
bare filename `ott-fingerprint.py` from your home folder is the most common
mistake and fails with `can't open file … No such file or directory`.

```bash
python3 ~/Documents/ott-fingerprint/ott-fingerprint.py "PASTE_MANIFEST_URL_IN_QUOTES"
```

Windows:

```bat
python "%USERPROFILE%\Documents\ott-fingerprint\ott-fingerprint.py" "PASTE_MANIFEST_URL_IN_QUOTES"
```

Everything below explains the details.

---

## System requirements

**Required**

- **Python 3.7 or newer.** Check with `python3 --version`.
  The core of the tool (HTTP headers, manifest parsing, MP4 box walking, the
  encoder-signature scan) is **pure Python standard library** — there is
  **nothing to `pip install`**. Copy the file and run it.
- **Operating system:** macOS, Linux, or Windows. Anywhere Python runs.
- **Network access** from the machine running the tool to the stream's host
  (the tool fetches the manifest and a small media sample over HTTPS).

**Optional but recommended**

- **ffmpeg / ffprobe** on your `PATH`. If present, the tool adds a structured
  codec / colour / HDR / frame-rate read of the sampled segment. If it is
  absent, the tool still runs end-to-end and simply prints a note that the
  structured codec read was skipped. Install it with:

  | OS | Command |
  | --- | --- |
  | macOS (Homebrew) | `brew install ffmpeg` |
  | Ubuntu / Debian | `sudo apt install ffmpeg` |
  | Windows | Download from <https://ffmpeg.org/download.html> and add to PATH |

  Confirm it is visible with `ffprobe -version`.

**Footprint / data use**

- By default the tool downloads the manifest plus **one init + one media
  segment** (capped at ~1.5 MB) from the *lowest* bitrate rendition, so a run
  transfers well under a few MB. Use `--no-deep` to fetch the manifest only and
  download **no** media bytes.

**What it does *not* need**

- No API keys, no accounts, no browser, no admin rights. It is one `.py` file.

---

## How to use

### Where the script lives, and how to run it

The tool ships as a **folder** containing `ott-fingerprint.py` and this README.
On the machine it was set up on, that folder is:

    ~/Documents/ott-fingerprint/

(`~` is shorthand for your home folder, e.g. `/Users/user`.) You can move the
folder anywhere — Downloads, a project directory, a USB stick. Python doesn't
care *where* it is; it only needs the **path you type to point at the file**.

**The mistake to avoid.** A new terminal window opens in your *home* folder
(`/Users/<you>`). If you type the bare filename there:

```bash
python3 ott-fingerprint.py "<url>"     # WRONG unless you are already inside the folder
```

you get this, because the script is not in your home folder — it's in
`Documents/ott-fingerprint/`:

    can't open file '/Users/<you>/ott-fingerprint.py': [Errno 2] No such file or directory

**The correct call**, either of these:

```bash
# CORRECT — Option A: give the full path to the script (works from any folder)
python3 ~/Documents/ott-fingerprint/ott-fingerprint.py "<url>"

# CORRECT — Option B: change into the script's folder first, then call it by name
cd ~/Documents/ott-fingerprint
python3 ott-fingerprint.py "<url>"
```

Windows full-path form:

```bat
python "%USERPROFILE%\Documents\ott-fingerprint\ott-fingerprint.py" "<url>"
```

Optional one-time setup — run it from anywhere as just `ott-fingerprint` by
making it executable and symlinking it onto your `PATH`:

```bash
chmod +x ~/Documents/ott-fingerprint/ott-fingerprint.py
sudo ln -s ~/Documents/ott-fingerprint/ott-fingerprint.py /usr/local/bin/ott-fingerprint
ott-fingerprint "<url>"          # now works from any folder
```

### 1. Find the manifest URL

Point the tool at the **master manifest** — the first playlist the player
loads. The easy way to find it:

1. Open the stream in a desktop browser.
2. Open DevTools (`F12` or right-click → Inspect) → **Network** tab.
3. Filter the requests for `m3u8` or `mpd`.
4. Start playback. The first matching request is the master manifest.
5. Right-click it → **Copy** → **Copy URL**.

### 2. Run it

```bash
python3 ~/Documents/ott-fingerprint/ott-fingerprint.py "https://example.com/path/master.m3u8"
```

Always **quote the URL** — streaming URLs contain `?`, `&` and `%` characters
that the shell would otherwise interpret. And use the **full path to the
script** (or `cd` into its folder first); if you see `can't open file …`, that's
the bare-filename mistake — see *Where the script lives* above.

### 3. Common variations

```bash
# Manifest only — fetch no media bytes (fastest, lightest touch)
python3 ott-fingerprint.py "https://example.com/stream.mpd" --no-deep

# Sample the TOP rendition instead of the lowest (more representative codec read)
python3 ott-fingerprint.py "https://example.com/master.m3u8" --variant highest

# Host with a self-signed / mismatched TLS cert you nonetheless trust
python3 ott-fingerprint.py "https://staging.example.com/master.m3u8" --insecure

# Machine-readable output for scripting / saving
python3 ott-fingerprint.py "https://example.com/master.m3u8" --json > report.json
```

### Options

| Option | Default | What it does |
| --- | --- | --- |
| `--no-deep` | off | Stop after the manifest; download no media segments. |
| `--variant {lowest,highest}` | `lowest` | Which rendition to sample for the deep probe. |
| `--max-bytes N` | `1500000` | Cap the per-segment download size, in bytes. |
| `--timeout S` | `20` | HTTP timeout, in seconds. |
| `--insecure` | off | Skip TLS certificate verification. |
| `--no-color` | off | Disable ANSI colour (use when piping to a file or a plain terminal). |
| `--json` | off | Print a JSON report after the human-readable summary. |

Run `python3 ott-fingerprint.py --help` for the built-in version of this list.

---

## Reading the output

The report is organised into the same phases the tool runs, cheapest first:

- **Phase 1 — HTTP / transport.** The HTTP status, the `Server`/`Via` headers,
  the inferred **CDN** (CloudFront, Fastly, Akamai, Cloudflare, Azure, Google,
  etc.) and how it was identified, plus any URL **auth scheme** (CloudFront
  signed URLs, Akamai tokens, JWTs).
- **Phase 2 — Manifest.** HLS vs DASH; protocol version / profiles; whether it
  is a master or media playlist; the full **ABR ladder** (resolutions,
  bitrates, codecs, frame rates); **HDR** signalling; audio/subtitle tracks;
  **DRM** systems; low-latency and trickplay markers; for DASH, the segment
  addressing style and any packager **generator comment**.
- **Phases 3–5 — Deep probe.** Downloads one init + one segment and reports the
  **container** (fragmented MP4/CMAF vs MPEG-TS), the `ftyp`/`styp` brands, the
  `hdlr` **muxer fingerprint**, DRM boxes (`pssh` system IDs, encryption scheme,
  `tenc`), the **encoder/muxer signature** scanned from the raw bytes (e.g. the
  full `x264 - core …` settings string, or `Lavf…` for FFmpeg), and the
  **ffprobe** codec / colour / frame-rate read.

### A note on accuracy

The transport, container, DRM, CDN and ladder findings are read directly from
bytes and headers, so they are reliable. **Encoder identification is
probabilistic**: mature production pipelines often strip the encoder settings
strings (the `x264 - core …` SEI) for size and security, in which case the tool
reports what it can see and the deeper conclusions become best-estimate rather
than certain. Forensic watermarking generally cannot be detected from a single
download — it requires diffing multiple sessions.

---

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `fetch failed: … CERTIFICATE …` | TLS cert is self-signed or mismatched. Re-run with `--insecure` **only if you trust the host**. |
| `HTTP 403` / `401` | The manifest needs auth, a token, or a specific region. Copy a *fresh* signed URL from the player's network log (tokens expire). |
| `Could not auto-locate a media segment` | Unusual manifest shape (e.g. exotic DASH addressing). The manifest-level findings (Phases 1–2) are still valid; the deep probe is what's skipped. |
| `ffprobe not on PATH — skipping…` | Install ffmpeg (see System requirements). Everything except the structured codec read still works. |
| Garbled colour codes in a log file | Add `--no-color`, or the tool auto-disables colour when output is not a terminal. |
| `url must start with http:// or https://` | Wrap the URL in quotes and include the scheme. |

---

## Sharing checklist

- The repo contains `ott-fingerprint.py` (the tool), this `README.md`, plus
  `LICENSE` and `CITATION.cff`. Send the whole folder, or just the script if
  that's all a teammate needs.
- Recipients need Python 3.7+; ffmpeg is optional.
- Reminder for the team: **authorised streams only**, and tokenised URLs expire,
  so grab a fresh one right before running.

---

## Licence

MIT — see [`LICENSE`](LICENSE). © 2026 jiggerbitties. Use and modification are
free; the licence only asks that the copyright notice travels with the code. If
you build on it or use it in published work, [`CITATION.cff`](CITATION.cff)
shows how to cite it (GitHub turns that file into a "Cite this repository"
button automatically).
