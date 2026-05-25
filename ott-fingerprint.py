#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ott-fingerprint.py  --  OTT / streaming supply-chain fingerprinter
===================================================================

Author:   jiggerbitties  ·  https://github.com/jiggerbitties/ott-fingerprint
Licence:  MIT (see the LICENSE file)
Version:  1.0.0

Point it at the manifest URL of an HLS (.m3u8) or DASH (.mpd) stream and it
infers as much of the upstream supply chain as the public output reveals:

    CDN / origin      -- from HTTP response headers and the host / URL shape
    Packager          -- from manifest dialect, segment naming, MP4 muxer tags
    Codec / encoder    -- from CODECS strings, ffprobe, and embedded SEI strings
    DRM               -- from manifest ContentProtection / EXT-X-KEY + pssh boxes
    ABR ladder        -- the rendition list (per-title vs fixed signatures)
    Ad insertion / LL -- SCTE-35 markers, low-latency tags, trickplay

It runs in phases of increasing cost:
    1. HTTP headers (one request, no media)
    2. Master manifest parse
    3. Media playlist + segment naming
    4. Download ONE init + ONE small segment, walk the MP4 boxes
    5. ffprobe + raw byte-scan of that segment for the encoder fingerprint

Phases 4-5 ("--deep", on by default) download a few hundred KB of media.
Use --no-deep to stop after the manifest (no media bytes fetched).

------------------------------------------------------------------------------
REQUIREMENTS  (designed to be portable / shareable)
------------------------------------------------------------------------------
  * Python 3.7+              -- the core (headers, manifests, MP4 boxes,
                                encoder-string scan) is PURE STDLIB, no pip.
  * ffmpeg / ffprobe         -- OPTIONAL. If present on PATH it adds structured
                                codec / colour / HDR / frame-rate detail.
                                If absent the tool still runs and says so.
                                  macOS:   brew install ffmpeg
                                  Ubuntu:  sudo apt install ffmpeg
                                  Windows: https://ffmpeg.org/download.html

------------------------------------------------------------------------------
USAGE
------------------------------------------------------------------------------
  python3 ott-fingerprint.py <manifest-url> [options]

  python3 ott-fingerprint.py https://example.com/master.m3u8
  python3 ott-fingerprint.py https://example.com/stream.mpd --no-deep
  python3 ott-fingerprint.py https://example.com/master.m3u8 --variant highest
  python3 ott-fingerprint.py https://example.com/master.m3u8 --json > report.json
  python3 ott-fingerprint.py https://example.com/master.m3u8 --insecure --no-color

Notes for sharing with coworkers:
  * Only fingerprints content you are authorised to access. It reads the same
    public manifests/segments a normal player would; it does not bypass DRM,
    auth, or geo controls. Respect each site's terms of service.
  * Point it at the *master* manifest URL (the one the player loads first).
    A browser DevTools "Network" tab, filtered to m3u8/mpd, is the easy way
    to find it; right-click -> Copy URL.
"""

__author__ = "jiggerbitties"
__version__ = "1.0.0"
__license__ = "MIT"
__url__ = "https://github.com/jiggerbitties/ott-fingerprint"

import argparse
import gzip
import io
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# ---------------------------------------------------------------------------
# Reference tables
# ---------------------------------------------------------------------------

DRM_SYSTEMS = {
    "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed": "Widevine (Google)",
    "9a04f079-9840-4286-ab92-e65be0885f95": "PlayReady (Microsoft)",
    "94ce86fb-07ff-4f43-adb8-93d2fa968ca2": "FairPlay (Apple)",
    "5e629af5-38da-4063-8977-97ffbd9902d4": "Marlin",
    "1077efec-c0b2-4d02-ace3-3c1e52e2fb4b": "ClearKey / W3C Common",
    "adb41c24-2dbf-4a6d-958b-4457c0d27b95": "Nagra",
    "6dd8b3c3-45f4-4a68-bf3a-64168d01a4a6": "ABV",
    "f239e769-efa3-4850-9c16-a903c6932efb": "Adobe PrimeTime",
    "279fe473-512c-48fe-ade8-d176fee6b40f": "Arris Titanium",
}

# fourcc / codec prefix -> human label
CODEC_NAMES = [
    ("avc1", "H.264/AVC"), ("avc3", "H.264/AVC"),
    ("hvc1", "HEVC/H.265"), ("hev1", "HEVC/H.265"),
    ("dvh1", "Dolby Vision (HEVC)"), ("dvhe", "Dolby Vision (HEVC)"),
    ("av01", "AV1"), ("vp09", "VP9"), ("vp08", "VP8"),
    ("mp4a", "AAC"), ("ec-3", "E-AC-3 / Dolby Digital Plus"),
    ("ac-3", "AC-3 / Dolby Digital"), ("ac-4", "AC-4 (Dolby)"),
    ("dtsc", "DTS"), ("dtse", "DTS Express"), ("opus", "Opus"),
    ("fLaC", "FLAC"), ("stpp", "TTML subtitles"), ("wvtt", "WebVTT subtitles"),
]

# Encoder / muxer byte signatures scanned in segment payloads.
# label -> regex (bytes). Capturing the trailing run gives the full settings.
ENCODER_SIGS = [
    ("x264",            rb"x264 - core[ -~]{0,400}"),
    ("x265",            rb"x265[ -~]{0,400}"),
    ("SVT-AV1",         rb"SVT-AV1[ -~]{0,200}"),
    ("libaom (AV1)",    rb"(?:aom-av1|AOMedia)[ -~]{0,200}"),
    ("libvpx",          rb"(?:Lavc[ -~]*libvpx|libvpx-vp9)[ -~]{0,80}"),
    ("FFmpeg (Lavf)",   rb"Lavf[0-9.]+"),
    ("FFmpeg (Lavc)",   rb"Lavc[0-9.]+[ -~]{0,120}"),
    ("GPAC / MP4Box",   rb"(?:GPAC|MP4Box|gpac)[ -~]{0,80}"),
    ("Bento4",          rb"Bento4[ -~]{0,80}"),
    ("HandBrake",       rb"HandBrake[ -~]{0,80}"),
    ("Unified Streaming", rb"(?:Unified Streaming|USP|mp4split)[ -~]{0,80}"),
    ("Shaka Packager",  rb"(?:shaka|Shaka)[ -~]{0,60}"),
    ("Elemental",       rb"(?:Elemental|MediaConvert)[ -~]{0,60}"),
    ("Apple CoreMedia", rb"Core Media[ -~]{0,40}"),
]

CONTAINER_BOXES = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"mvex",
                   b"moof", b"traf", b"udta", b"edts", b"dinf", b"sinf",
                   b"schi", b"mfra", b"stsd"}

# ---------------------------------------------------------------------------
# Colour / output helpers
# ---------------------------------------------------------------------------

class C:
    enabled = True
    @classmethod
    def wrap(cls, s, code):
        if not cls.enabled:
            return s
        return "\033[%sm%s\033[0m" % (code, s)
    @classmethod
    def bold(cls, s):  return cls.wrap(s, "1")
    @classmethod
    def dim(cls, s):   return cls.wrap(s, "2")
    @classmethod
    def cyan(cls, s):  return cls.wrap(s, "36")
    @classmethod
    def green(cls, s): return cls.wrap(s, "32")
    @classmethod
    def yellow(cls, s):return cls.wrap(s, "33")
    @classmethod
    def red(cls, s):   return cls.wrap(s, "31")
    @classmethod
    def mag(cls, s):   return cls.wrap(s, "35")


def hr():
    return C.dim("-" * 74)


def section(title):
    print()
    print(C.bold(C.cyan("== " + title + " ")) + C.cyan("=" * max(0, 70 - len(title))))


def kv(key, val, key_w=22):
    if val is None or val == "":
        val = C.dim("-")
    print("  %s %s" % ((key + ":").ljust(key_w), val))


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def http_get(url, timeout=20, insecure=False, range_bytes=None, head=False):
    """Return dict: status, headers(list of (k,v)), body(bytes), final_url, error."""
    headers = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "gzip, identity"}
    if range_bytes is not None:
        headers["Range"] = "bytes=%d-%d" % (range_bytes[0], range_bytes[1])
    method = "HEAD" if head else "GET"
    req = urllib.request.Request(url, headers=headers, method=method)
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    out = {"status": None, "headers": [], "body": b"", "final_url": url, "error": None}
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            out["status"] = r.status
            out["headers"] = list(r.headers.items())
            out["final_url"] = r.geturl()
            body = b"" if head else r.read()
            if r.headers.get("Content-Encoding", "").lower() == "gzip" and body:
                try:
                    body = gzip.decompress(body)
                except OSError:
                    pass
            out["body"] = body
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        out["headers"] = list(e.headers.items()) if e.headers else []
        out["error"] = "HTTP %s" % e.code
        try:
            out["body"] = e.read()
        except Exception:
            pass
    except (urllib.error.URLError, socket.timeout, ssl.SSLError) as e:
        out["error"] = str(getattr(e, "reason", e))
    except Exception as e:  # noqa
        out["error"] = "%s: %s" % (type(e).__name__, e)
    return out


def header_get(headers, name):
    name = name.lower()
    vals = [v for (k, v) in headers if k.lower() == name]
    return vals[0] if vals else None


# ---------------------------------------------------------------------------
# CDN / origin inference
# ---------------------------------------------------------------------------

def infer_cdn(headers, url):
    hits = []
    hd = {k.lower(): v for (k, v) in headers}
    server = (hd.get("server") or "")
    via = (hd.get("via") or "")
    def has(*names):
        return [n for n in names if n.lower() in hd]

    if "x-amz-cf-id" in hd or "x-amz-cf-pop" in hd or "cloudfront" in via.lower() \
            or "cloudfront" in (hd.get("x-cache", "").lower()):
        pop = hd.get("x-amz-cf-pop", "")
        hits.append(("Amazon CloudFront", "x-amz-cf-* / Via" + ((" pop=" + pop) if pop else "")))
    if has("x-served-by", "x-timer") and ("varnish" in via.lower() or "x-served-by" in hd):
        hits.append(("Fastly", "x-served-by / x-timer / Via:varnish"))
    if "akamaighost" in server.lower() or any(k.startswith("x-akamai") for k in hd) \
            or "akamai" in via.lower():
        hits.append(("Akamai", "Server/Via/x-akamai-*"))
    if "cf-ray" in hd or server.lower() == "cloudflare":
        hits.append(("Cloudflare", "cf-ray / Server:cloudflare"))
    if "x-msedge-ref" in hd or "x-azure-ref" in hd or "x-ms-ref" in hd:
        hits.append(("Microsoft Azure CDN", "x-(ms)edge/azure-ref"))
    if "1.1 google" in via.lower() or any(k.startswith("x-goog") for k in hd):
        hits.append(("Google Cloud CDN/Media", "Via:google / x-goog-*"))
    if "limelight" in server.lower() or "llnw" in (url.lower()):
        hits.append(("Limelight / Edgio", "Server / host"))
    if "bunnycdn" in server.lower() or "bunny" in via.lower():
        hits.append(("Bunny CDN", "Server/Via"))
    if "x-cdn" in hd:
        hits.append((hd["x-cdn"], "x-cdn header"))
    # host-based hints
    host = urllib.parse.urlparse(url).hostname or ""
    host_map = [
        ("akamaihd.net", "Akamai (akamaihd host)"),
        ("akamaized.net", "Akamai (akamaized host)"),
        ("cloudfront.net", "Amazon CloudFront (host)"),
        ("fastly.net", "Fastly (host)"),
        ("llnwd.net", "Limelight/Edgio (host)"),
        ("footprint.net", "Edgecast/Edgio (host)"),
        ("azureedge.net", "Azure CDN (host)"),
        ("b-cdn.net", "Bunny CDN (host)"),
        ("cdn77", "CDN77 (host)"),
    ]
    for needle, label in host_map:
        if needle in host and not any(label.split()[0] in h[0] for h in hits):
            hits.append((label, "hostname"))
    return hits, server, via


def auth_scheme(url):
    q = urllib.parse.urlparse(url).query.lower()
    notes = []
    if "key-pair-id" in q or ("signature" in q and "expires" in q):
        notes.append("CloudFront signed URL (Key-Pair-Id/Signature/Expires)")
    if "hdnts=" in q or "hdntl=" in q or "__token__" in q:
        notes.append("Akamai token auth (hdnts/hdntl)")
    if re.search(r"[?&]token=ey[a-z0-9_\-]+\.", q):
        notes.append("JWT token (?token=)")
    if "policy=" in q and "signature=" in q:
        notes.append("Signed policy URL")
    return notes


# ---------------------------------------------------------------------------
# Manifest parsing -- HLS
# ---------------------------------------------------------------------------

def absurl(base, ref):
    return urllib.parse.urljoin(base, ref)


def parse_attrs(s):
    """Parse comma-separated KEY=VALUE list, respecting quoted values."""
    out = {}
    for m in re.finditer(r'([A-Z0-9\-]+)=("[^"]*"|[^,]*)', s):
        k = m.group(1)
        v = m.group(2)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[k] = v
    return out


def parse_hls_master(text, base_url):
    info = {
        "type": "HLS", "is_master": False, "version": None,
        "variants": [], "audio": [], "subtitles": [], "iframe": [],
        "trickplay": False, "session_keys": [], "low_latency": False,
        "raw_independent": False,
    }
    lines = [l.strip() for l in text.splitlines()]
    pending = None
    for i, line in enumerate(lines):
        if line.startswith("#EXT-X-VERSION:"):
            info["version"] = line.split(":", 1)[1].strip()
        elif line.startswith("#EXT-X-INDEPENDENT-SEGMENTS"):
            info["raw_independent"] = True
        elif line.startswith("#EXT-X-STREAM-INF:"):
            info["is_master"] = True
            pending = parse_attrs(line.split(":", 1)[1])
        elif line.startswith("#EXT-X-MEDIA:"):
            a = parse_attrs(line.split(":", 1)[1])
            t = a.get("TYPE", "")
            entry = {"group": a.get("GROUP-ID"), "name": a.get("NAME"),
                     "lang": a.get("LANGUAGE"), "uri": a.get("URI"),
                     "channels": a.get("CHANNELS"), "default": a.get("DEFAULT")}
            if t == "AUDIO":
                info["audio"].append(entry)
            elif t in ("SUBTITLES", "CLOSED-CAPTIONS"):
                info["subtitles"].append(entry)
        elif line.startswith("#EXT-X-I-FRAME-STREAM-INF:"):
            a = parse_attrs(line.split(":", 1)[1])
            info["iframe"].append(a)
        elif line.startswith("#EXT-X-IMAGE-STREAM-INF:") or "IMAGE-STREAM" in line:
            info["trickplay"] = True
        elif line.startswith("#EXT-X-SESSION-KEY:"):
            info["session_keys"].append(parse_attrs(line.split(":", 1)[1]))
        elif line.startswith("#EXT-X-PART") or "PRELOAD-HINT" in line or \
                line.startswith("#EXT-X-SERVER-CONTROL") and "CAN-BLOCK-RELOAD" in line:
            info["low_latency"] = True
        elif pending is not None and line and not line.startswith("#"):
            pending["URI"] = absurl(base_url, line)
            info["variants"].append(pending)
            pending = None
    return info


def parse_hls_media(text, base_url):
    """Return dict with init segment, first segment, drm keys, scte, ll, seg ext."""
    out = {"init": None, "init_byterange": None, "first_seg": None,
           "first_byterange": None, "keys": [], "scte": [], "low_latency": False,
           "seg_ext": None, "target_duration": None, "playlist_type": None,
           "program_date_time": False}
    lines = [l.strip() for l in text.splitlines()]
    pending_range = None
    for i, line in enumerate(lines):
        if line.startswith("#EXT-X-MAP:"):
            a = parse_attrs(line.split(":", 1)[1])
            if a.get("URI"):
                out["init"] = absurl(base_url, a["URI"])
            out["init_byterange"] = a.get("BYTERANGE")
        elif line.startswith("#EXT-X-KEY:") or line.startswith("#EXT-X-SESSION-KEY:"):
            out["keys"].append(parse_attrs(line.split(":", 1)[1]))
        elif line.startswith("#EXT-X-TARGETDURATION:"):
            out["target_duration"] = line.split(":", 1)[1].strip()
        elif line.startswith("#EXT-X-PLAYLIST-TYPE:"):
            out["playlist_type"] = line.split(":", 1)[1].strip()
        elif line.startswith("#EXT-X-PROGRAM-DATE-TIME"):
            out["program_date_time"] = True
        elif line.startswith("#EXT-X-DATERANGE") and "SCTE35" in line.upper():
            out["scte"].append("EXT-X-DATERANGE/SCTE35")
        elif "EXT-OATCLS-SCTE35" in line or "EXT-X-CUE-OUT" in line or "EXT-X-SCTE35" in line:
            out["scte"].append(line.split(":", 1)[0].lstrip("#"))
        elif line.startswith("#EXT-X-PART") or "PRELOAD-HINT" in line:
            out["low_latency"] = True
        elif line.startswith("#EXT-X-BYTERANGE:"):
            pending_range = line.split(":", 1)[1].strip()
        elif line and not line.startswith("#"):
            if out["first_seg"] is None:
                out["first_seg"] = absurl(base_url, line)
                out["first_byterange"] = pending_range
                out["seg_ext"] = os.path.splitext(urllib.parse.urlparse(line).path)[1].lower()
            pending_range = None
    return out


# ---------------------------------------------------------------------------
# Manifest parsing -- DASH
# ---------------------------------------------------------------------------

def _localname(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def _findall_local(elem, name):
    return [e for e in elem.iter() if _localname(e.tag) == name]


def _children_local(elem, name):
    return [e for e in elem if _localname(e.tag) == name]


def parse_dash(text, base_url):
    info = {"type": "DASH", "profiles": None, "mpd_type": None,
            "min_buffer": None, "namespaces": [], "generator": None,
            "drm": [], "representations": [], "thumbnails": False,
            "utc_timing": [], "seg_addressing": set(), "low_latency": False,
            "first_segment_url": None, "first_init_url": None}
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        info["error"] = "MPD parse error: %s" % e
        return info
    info["profiles"] = root.get("profiles")
    info["mpd_type"] = root.get("type", "static")
    info["min_buffer"] = root.get("minBufferTime")
    # namespaces (collected from attribute keys / xmlns is not in attrib easily) -> scan text
    for m in re.finditer(r'xmlns:?\w*="([^"]+)"', text):
        if m.group(1) not in info["namespaces"]:
            info["namespaces"].append(m.group(1))
    cm = re.search(r"<!--\s*(.*?)\s*-->", text, re.S)
    if cm:
        info["generator"] = cm.group(1).strip()[:160]
    # base url chain
    mpd_base = base_url
    bu = _children_local(root, "BaseURL")
    if bu and bu[0].text:
        mpd_base = absurl(base_url, bu[0].text.strip())
    # UTCTiming
    for u in _findall_local(root, "UTCTiming"):
        info["utc_timing"].append("%s %s" % (u.get("schemeIdUri", ""), u.get("value", "")))
    # ContentProtection
    seen = set()
    for cp in _findall_local(root, "ContentProtection"):
        sid = (cp.get("schemeIdUri") or "").lower().replace("urn:uuid:", "")
        val = cp.get("value") or cp.get("{urn:mpeg:cenc:2013}default_KID")
        label = DRM_SYSTEMS.get(sid)
        key = sid or (cp.get("schemeIdUri") or "")
        if key in seen:
            continue
        seen.add(key)
        if label:
            info["drm"].append((label, sid))
        elif "mp4protection" in (cp.get("schemeIdUri") or ""):
            info["drm"].append(("Common Encryption (mp4protection)", cp.get("value") or ""))
        elif sid:
            info["drm"].append(("Unknown DRM " + sid, sid))
    # Low-latency DASH is only meaningful on live (dynamic) manifests: look for
    # an explicit Latency target, the DVB LL scheme, or an availabilityTimeOffset
    # on a dynamic MPD. (A static/VOD MPD is never low-latency.)
    if "<Latency" in text or "urn:dvb:dash:lowlatency" in text:
        info["low_latency"] = True
    elif info["mpd_type"] == "dynamic" and "availabilityTimeOffset" in text:
        info["low_latency"] = True
    # thumbnails
    for ad in _findall_local(root, "AdaptationSet"):
        ct = (ad.get("contentType") or "") + (ad.get("mimeType") or "")
        if "image" in ct.lower():
            info["thumbnails"] = True
        for ev in _findall_local(ad, "EssentialProperty"):
            if "thumbnail" in (ev.get("schemeIdUri") or "").lower():
                info["thumbnails"] = True
    # representations + first segment locate
    period = None
    for p in _findall_local(root, "Period"):
        period = p
        break
    if period is None:
        return info
    pbase = mpd_base
    pb = _children_local(period, "BaseURL")
    if pb and pb[0].text:
        pbase = absurl(mpd_base, pb[0].text.strip())
    for aset in _children_local(period, "AdaptationSet"):
        abase = pbase
        ab = _children_local(aset, "BaseURL")
        if ab and ab[0].text:
            abase = absurl(pbase, ab[0].text.strip())
        a_ct = aset.get("contentType") or aset.get("mimeType") or ""
        a_codecs = aset.get("codecs")
        # adaptationset-level template
        aset_tmpl = (_children_local(aset, "SegmentTemplate") or [None])[0]
        reps = _children_local(aset, "Representation")
        for rep in reps:
            r = {"id": rep.get("id"), "bw": rep.get("bandwidth"),
                 "w": rep.get("width"), "h": rep.get("height"),
                 "codecs": rep.get("codecs") or a_codecs,
                 "mime": rep.get("mimeType") or aset.get("mimeType"),
                 "frate": rep.get("frameRate") or aset.get("frameRate"),
                 "ct": a_ct}
            info["representations"].append(r)
        # pick the first video rep to derive a segment URL for deep probe
        is_video = "video" in (a_ct.lower() + (aset.get("mimeType") or "").lower())
        if is_video and info["first_segment_url"] is None and reps:
            rep = sorted(reps, key=lambda x: int(x.get("bandwidth") or 0))[0]
            tmpl = (_children_local(rep, "SegmentTemplate") or [aset_tmpl])[0]
            if tmpl is not None:
                info["seg_addressing"].add("SegmentTemplate" +
                                           ("+Timeline" if _children_local(tmpl, "SegmentTimeline") else "+Number"))
                init_t = tmpl.get("initialization")
                media_t = tmpl.get("media")
                start = int(tmpl.get("startNumber", "1"))
                first_time = 0
                stl = _children_local(tmpl, "SegmentTimeline")
                if stl:
                    s0 = _children_local(stl[0], "S")
                    if s0:
                        first_time = int(s0[0].get("t", "0"))
                ctx = {"RepresentationID": rep.get("id") or "",
                       "Bandwidth": rep.get("bandwidth") or "0",
                       "Number": str(start), "Time": str(first_time)}
                if init_t:
                    info["first_init_url"] = absurl(abase, _sub_template(init_t, ctx))
                if media_t:
                    info["first_segment_url"] = absurl(abase, _sub_template(media_t, ctx))
            else:
                sl = (_children_local(rep, "SegmentList") or [None])[0]
                sb = (_children_local(rep, "SegmentBase") or [None])[0]
                rbu = _children_local(rep, "BaseURL")
                rbase = absurl(abase, rbu[0].text.strip()) if (rbu and rbu[0].text) else abase
                if sl is not None:
                    info["seg_addressing"].add("SegmentList")
                    ini = (_children_local(sl, "Initialization") or [None])[0]
                    if ini is not None and ini.get("sourceURL"):
                        info["first_init_url"] = absurl(rbase, ini.get("sourceURL"))
                    surls = _children_local(sl, "SegmentURL")
                    if surls and surls[0].get("media"):
                        info["first_segment_url"] = absurl(rbase, surls[0].get("media"))
                elif sb is not None or rbu:
                    info["seg_addressing"].add("SegmentBase (single-file on-demand)")
                    # single-file: range-fetch the head to get ftyp+moov
                    info["first_init_url"] = rbase
                    info["first_segment_url"] = None
    return info


def _sub_template(tmpl, ctx):
    def repl(m):
        token = m.group(1)
        fmt = m.group(2)
        if token == "":  # literal $$
            return "$"
        val = ctx.get(token, "")
        if fmt and val.isdigit():
            try:
                return ("%" + fmt) % int(val)
            except (ValueError, TypeError):
                return val
        return val
    return re.sub(r"\$(\w*)(?:%0?\d*d)?\$", lambda m: _sub_one(m, ctx), tmpl)


def _sub_one(m, ctx):
    full = m.group(0)  # like $Number%05d$ or $RepresentationID$
    inner = full[1:-1]
    if inner == "":
        return "$"
    fmt = None
    if "%" in inner:
        token, fmt = inner.split("%", 1)
        fmt = "%" + fmt
    else:
        token = inner
    val = ctx.get(token, "")
    if fmt and str(val).isdigit():
        try:
            return fmt % int(val)
        except (ValueError, TypeError):
            return str(val)
    return str(val)


# ---------------------------------------------------------------------------
# MP4 box walking (pure python)
# ---------------------------------------------------------------------------

def iter_boxes(data, start, end):
    pos = start
    while pos + 8 <= end:
        size = struct.unpack(">I", data[pos:pos + 4])[0]
        typ = data[pos + 4:pos + 8]
        header = 8
        if size == 1:
            if pos + 16 > end:
                break
            size = struct.unpack(">Q", data[pos + 8:pos + 16])[0]
            header = 16
        elif size == 0:
            size = end - pos
        if size < header or pos + size > end:
            # tolerate truncated final box (segment may be partial)
            yield typ, pos, header, end - pos
            return
        yield typ, pos, header, size
        pos += size


def walk_mp4(data):
    """Recursively collect notable boxes. Returns dict of findings."""
    f = {"brands": [], "handlers": [], "pssh": [], "schm": [], "tenc": [],
         "has_prft": False, "has_styp": False, "styp_brands": [], "has_sidx": False,
         "top_boxes": [], "is_fmp4": False, "is_ts": False}

    def recurse(start, end, depth=0):
        for typ, pos, header, size in iter_boxes(data, start, end):
            t = typ.decode("latin1", "replace")
            if depth == 0:
                f["top_boxes"].append(t)
            payload_s, payload_e = pos + header, pos + size
            if typ == b"ftyp" or typ == b"styp":
                if typ == b"styp":
                    f["has_styp"] = True
                major = data[payload_s:payload_s + 4].decode("latin1", "replace")
                brands = [major]
                p = payload_s + 8
                while p + 4 <= payload_e:
                    b = data[p:p + 4].decode("latin1", "replace").strip()
                    if b:
                        brands.append(b)
                    p += 4
                if typ == b"ftyp":
                    f["brands"] = brands
                    f["is_fmp4"] = True
                else:
                    f["styp_brands"] = brands
            elif typ == b"hdlr":
                # version+flags(4) predef(4) handler_type(4) reserved(12) name...
                htype = data[payload_s + 8:payload_s + 12].decode("latin1", "replace")
                name = data[payload_s + 24:payload_e].split(b"\x00", 1)[0]
                name = name.decode("utf-8", "replace").strip()
                f["handlers"].append((htype, name))
            elif typ == b"pssh":
                sysid = data[payload_s + 4:payload_s + 20]
                if len(sysid) == 16:
                    f["pssh"].append(_uuid(sysid))
            elif typ == b"schm":
                stype = data[payload_s + 4:payload_s + 8].decode("latin1", "replace")
                f["schm"].append(stype)
            elif typ == b"tenc":
                # version+flags(4) reserved(1) (crypt/skip or reserved)(1) isProtected(1) ivsize(1) KID(16)
                try:
                    is_prot = data[payload_s + 6]
                    kid = data[payload_s + 8:payload_s + 24]
                    f["tenc"].append((is_prot, _uuid(kid)))
                except IndexError:
                    pass
            elif typ == b"prft":
                f["has_prft"] = True
            elif typ == b"sidx":
                f["has_sidx"] = True
            if typ in CONTAINER_BOXES:
                inner_start = payload_s
                if typ == b"meta":
                    inner_start = payload_s + 4  # meta is a FullBox
                recurse(inner_start, payload_e, depth + 1)
        return

    # meta needs to be in container set but with offset; add handling
    CONTAINER_BOXES.add(b"meta")
    # detect MPEG-TS first (sync byte every 188)
    if len(data) >= 188 * 2 and data[0] == 0x47 and data[188] == 0x47:
        f["is_ts"] = True
        return f
    try:
        recurse(0, len(data))
    except Exception as e:  # noqa - be forgiving on weird/partial data
        f["walk_error"] = str(e)
    # raw fallback: tenc/schm live inside sample entries which the plain walk
    # may not align to. Scan the buffer directly and merge anything new.
    _raw_scan_crypto(data, f)
    return f


def _raw_scan_crypto(data, f):
    """Find pssh/schm/tenc anywhere in the buffer, even when nested in sample
    entries the recursive walk can't align to. Merge into findings dict."""
    for tok in (b"pssh", b"schm", b"tenc"):
        start = 0
        while True:
            idx = data.find(tok, start)
            if idx < 4:
                if idx == -1:
                    break
                start = idx + 4
                continue
            start = idx + 4
            box_start = idx - 4
            try:
                size = struct.unpack(">I", data[box_start:box_start + 4])[0]
            except struct.error:
                continue
            if size < 12 or box_start + size > len(data):
                continue
            ps = box_start + 8  # FullBox payload (after size+type)
            if tok == b"pssh":
                sysid = data[ps + 4:ps + 20]
                if len(sysid) == 16:
                    u = _uuid(sysid)
                    if u not in f["pssh"]:
                        f["pssh"].append(u)
            elif tok == b"schm":
                stype = data[ps + 4:ps + 8].decode("latin1", "replace")
                if stype and stype not in f["schm"]:
                    f["schm"].append(stype)
            elif tok == b"tenc":
                try:
                    is_prot = data[ps + 6]
                    kid = _uuid(data[ps + 8:ps + 24])
                    if (is_prot, kid) not in f["tenc"]:
                        f["tenc"].append((is_prot, kid))
                except IndexError:
                    pass


def _uuid(b):
    h = b.hex()
    return "%s-%s-%s-%s-%s" % (h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])


def scan_encoder_sigs(data):
    found = []
    seen = set()
    for label, pat in ENCODER_SIGS:
        for m in re.finditer(pat, data):
            s = m.group(0).decode("latin1", "replace")
            s = re.sub(r"[^\x20-\x7e]+", " ", s).strip()
            key = (label, s[:60])
            if key in seen:
                continue
            seen.add(key)
            found.append((label, s[:300]))
            if len(found) > 25:
                return found
    return found


# ---------------------------------------------------------------------------
# ffprobe
# ---------------------------------------------------------------------------

def have_ffprobe():
    return shutil.which("ffprobe") is not None


def ffprobe_bytes(data, ext):
    if not have_ffprobe():
        return None
    tf = tempfile.NamedTemporaryFile(suffix=ext or ".bin", delete=False)
    try:
        tf.write(data)
        tf.close()
        cmd = ["ffprobe", "-v", "error", "-print_format", "json",
               "-show_format", "-show_streams", tf.name]
        out = subprocess.run(cmd, capture_output=True, timeout=30)
        if out.returncode != 0 or not out.stdout:
            return {"_stderr": out.stderr.decode("utf-8", "replace")[:300]}
        return json.loads(out.stdout.decode("utf-8", "replace"))
    except Exception as e:  # noqa
        return {"_error": str(e)}
    finally:
        try:
            os.unlink(tf.name)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Codec helpers
# ---------------------------------------------------------------------------

def codec_label(codec_str):
    if not codec_str:
        return None
    parts = [p.strip() for p in codec_str.split(",")]
    labels = []
    for p in parts:
        pre = p[:4]
        name = next((n for k, n in CODEC_NAMES if k == pre), None)
        labels.append("%s (%s)" % (name, p) if name else p)
    return ", ".join(labels)


def hdr_from_codecs(codec_str, video_range=None):
    notes = []
    if video_range and video_range.upper() in ("PQ", "HLG"):
        notes.append("HDR: " + video_range.upper())
    if codec_str:
        cs = codec_str.lower()
        if "dvh" in cs or "dav1" in cs:
            notes.append("Dolby Vision")
        if re.search(r"hvc1\.2|hev1\.2", cs):
            notes.append("HEVC Main10 (HDR-capable)")
    return notes


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def fmt_bw(bw):
    try:
        b = int(bw)
    except (TypeError, ValueError):
        return str(bw)
    if b >= 1_000_000:
        return "%.2f Mbps" % (b / 1_000_000)
    return "%.0f kbps" % (b / 1000)


def run(url, args):
    report = {"url": url, "phases": {}}
    if not C.enabled:
        pass

    print(hr())
    print(C.bold(" OTT supply-chain fingerprint"))
    print("  target: " + C.yellow(url))
    print(hr())

    # ---- Phase 1: HTTP / headers
    section("Phase 1  ·  HTTP / transport")
    r = http_get(url, timeout=args.timeout, insecure=args.insecure)
    if r["error"] and not r["body"]:
        print(C.red("  fetch failed: %s" % r["error"]))
        if "CERTIFICATE" in str(r["error"]).upper():
            print(C.dim("  (try --insecure if you trust this host)"))
        return report
    kv("HTTP status", r["status"])
    if r["final_url"] != url:
        kv("Redirected to", r["final_url"])
    cdns, server, via = infer_cdn(r["headers"], r["final_url"])
    kv("Server header", server or None)
    kv("Via header", via or None)
    if cdns:
        for name, why in cdns:
            print("  %s %s  %s" % ("CDN:".ljust(22), C.green(name), C.dim("(" + why + ")")))
    else:
        kv("CDN", C.dim("no signature in headers"))
    auth = auth_scheme(r["final_url"])
    if auth:
        kv("URL auth", "; ".join(auth))
    for h in ("content-type", "cache-control", "age", "x-cache", "access-control-allow-origin"):
        v = header_get(r["headers"], h)
        if v:
            kv(h, v)
    report["phases"]["http"] = {"status": r["status"], "cdn": cdns,
                                "server": server, "via": via, "auth": auth}

    body = r["body"].decode("utf-8", "replace")
    base_url = r["final_url"]

    # ---- Phase 2: manifest type + master parse
    section("Phase 2  ·  Manifest")
    is_hls = body.lstrip().startswith("#EXTM3U")
    is_dash = ("<MPD" in body[:2000]) or body.lstrip().startswith("<?xml")
    seg_target = None  # (init_url, seg_url, seg_ext, byteranges)

    if is_hls:
        m = parse_hls_master(body, base_url)
        kv("Format", "HLS  (#EXTM3U)")
        kv("HLS version", m["version"])
        kv("Manifest kind", "Master/multivariant" if m["is_master"] else "Media playlist")
        if m["low_latency"]:
            kv("Low latency", C.mag("LL-HLS tags present (EXT-X-PART / PRELOAD-HINT)"))
        if m["trickplay"]:
            kv("Trickplay", "EXT-X-IMAGE-STREAM-INF present")
        # ABR ladder
        if m["variants"]:
            print()
            print("  " + C.bold("ABR ladder (%d renditions):" % len(m["variants"])))
            for v in sorted(m["variants"], key=lambda x: int(x.get("BANDWIDTH", 0) or 0)):
                res = v.get("RESOLUTION", "?")
                fr = v.get("FRAME-RATE", "")
                vr = v.get("VIDEO-RANGE", "")
                cod = codec_label(v.get("CODECS", "")) or v.get("CODECS", "")
                line = "    %-11s %-10s %s" % (res, fmt_bw(v.get("BANDWIDTH")),
                                               C.dim(cod))
                if fr:
                    line += C.dim("  @%sfps" % fr)
                if vr and vr != "SDR":
                    line += "  " + C.mag(vr)
                print(line)
            hdr_notes = []
            for v in m["variants"]:
                hdr_notes += hdr_from_codecs(v.get("CODECS"), v.get("VIDEO-RANGE"))
            if hdr_notes:
                kv("HDR signalling", ", ".join(sorted(set(hdr_notes))))
        if m["audio"]:
            kv("Audio groups", ", ".join(
                "%s/%s%s" % (a.get("lang") or "?", a.get("name") or "?",
                             ("/" + a["channels"] + "ch") if a.get("channels") else "")
                for a in m["audio"][:6]))
        if m["subtitles"]:
            kv("Subtitle/CC", ", ".join(
                "%s" % (s.get("lang") or s.get("name") or "?") for s in m["subtitles"][:8]))
        # DRM from session keys
        drm = drm_from_hls_keys(m["session_keys"])
        if drm:
            kv("DRM (session-key)", ", ".join(drm))
        report["phases"]["manifest"] = {"format": "HLS", "version": m["version"],
                                        "renditions": len(m["variants"])}
        # choose a variant to descend into
        seg_target = locate_hls_segment(m, base_url, args)

    elif is_dash:
        d = parse_dash(body, base_url)
        if d.get("error"):
            print(C.red("  " + d["error"]))
            return report
        kv("Format", "DASH (MPD)")
        kv("Profiles", d["profiles"])
        kv("MPD type", d["mpd_type"] + ("  (live)" if d["mpd_type"] == "dynamic" else "  (VOD)"))
        if d["generator"]:
            kv("Generator comment", C.green(d["generator"]))
        if d["namespaces"]:
            kv("Namespaces", C.dim(", ".join(d["namespaces"][:5])))
        if d["seg_addressing"]:
            kv("Segment addressing", ", ".join(sorted(d["seg_addressing"])))
        if d["low_latency"]:
            kv("Low latency", C.mag("LL-DASH hints (ServiceDescription / ATO)"))
        if d["utc_timing"]:
            kv("UTCTiming", "; ".join(d["utc_timing"][:2]))
        if d["thumbnails"]:
            kv("Trickplay", "thumbnail AdaptationSet present")
        vids = [r for r in d["representations"] if "video" in (r["ct"] + (r["mime"] or "")).lower()]
        if vids:
            print()
            print("  " + C.bold("ABR ladder (%d video reps):" % len(vids)))
            for v in sorted(vids, key=lambda x: int(x.get("bw") or 0)):
                res = ("%sx%s" % (v["w"], v["h"])) if v.get("w") else "?"
                print("    %-11s %-10s %s" % (res, fmt_bw(v.get("bw")),
                                              C.dim(codec_label(v.get("codecs")) or "")))
            hdr_notes = []
            for v in vids:
                hdr_notes += hdr_from_codecs(v.get("codecs"))
            if hdr_notes:
                kv("HDR signalling", ", ".join(sorted(set(hdr_notes))))
        if d["drm"]:
            kv("DRM", ", ".join("%s" % name for name, _ in d["drm"]))
        report["phases"]["manifest"] = {"format": "DASH", "profiles": d["profiles"],
                                        "drm": [n for n, _ in d["drm"]]}
        if not args.no_deep and (d["first_segment_url"] or d["first_init_url"]):
            seg_target = {"init": d["first_init_url"], "seg": d["first_segment_url"],
                          "ext": ".m4s", "init_range": None, "seg_range": None,
                          "single_file": d["first_segment_url"] is None}
    else:
        kv("Format", C.red("unrecognised — not HLS (#EXTM3U) or DASH (<MPD>)"))
        print(C.dim("  First 200 bytes:"))
        print(C.dim("  " + body[:200].replace("\n", " ")))
        return report

    # ---- Phase 3/4/5: deep probe
    if args.no_deep:
        print()
        print(C.dim("  [--no-deep] stopping before any media download."))
        return report
    if not seg_target or not (seg_target.get("init") or seg_target.get("seg")):
        section("Phase 3-5  ·  Deep probe")
        print(C.yellow("  Could not auto-locate a media segment to download "
                       "(unusual manifest shape)."))
        return report

    deep_probe(seg_target, args, report)
    return report


def drm_from_hls_keys(keys):
    out = []
    for k in keys:
        kf = (k.get("KEYFORMAT") or "").lower()
        method = k.get("METHOD", "")
        if "streamingkeydelivery" in kf or (k.get("URI", "").startswith("skd")):
            out.append("FairPlay (Apple)")
        elif "playready" in kf:
            out.append("PlayReady (Microsoft)")
        elif "edef8ba9" in kf:
            out.append("Widevine (Google)")
        elif method and method != "NONE":
            out.append("AES (%s)" % method)
    return sorted(set(out))


def locate_hls_segment(master, base_url, args):
    """Descend from master to a media playlist and grab init + first segment."""
    if not master["variants"]:
        # body itself may be a media playlist
        return None
    chooser = max if args.variant == "highest" else min
    var = chooser(master["variants"], key=lambda x: int(x.get("BANDWIDTH", 0) or 0))
    media_url = var.get("URI")
    if not media_url:
        return None
    r = http_get(media_url, timeout=args.timeout, insecure=args.insecure)
    if r["error"] and not r["body"]:
        return None
    media = parse_hls_media(r["body"].decode("utf-8", "replace"), r["final_url"])
    return {"init": media["init"], "seg": media["first_seg"],
            "ext": media["seg_ext"] or ".ts",
            "init_range": media["init_byterange"], "seg_range": media["first_byterange"],
            "media_meta": media, "single_file": False}


def _range_tuple(br):
    """HLS BYTERANGE 'len@off' -> (off, off+len-1)."""
    if not br:
        return None
    if "@" in br:
        length, off = br.split("@")
        length, off = int(length), int(off)
    else:
        length, off = int(br), 0
    return (off, off + length - 1)


def fetch_media(url, args, byterange=None, single_file=False):
    rb = _range_tuple(byterange)
    if rb is None and single_file:
        rb = (0, args.max_bytes - 1)
    elif rb is None:
        # cap the download even without an explicit byterange
        rb = (0, args.max_bytes - 1)
    r = http_get(url, timeout=args.timeout, insecure=args.insecure, range_bytes=rb)
    return r


def deep_probe(target, args, report):
    section("Phase 3-5  ·  Deep probe (one init + one segment)")
    blobs = []
    init_url = target.get("init")
    seg_url = target.get("seg")
    single = target.get("single_file")

    if init_url:
        kv("Init segment", short_url(init_url))
        ri = fetch_media(init_url, args, target.get("init_range"), single_file=single)
        if ri["body"]:
            blobs.append(ri["body"])
            kv("  fetched", "%d bytes (HTTP %s)" % (len(ri["body"]), ri["status"]))
            ic, iv, _ = infer_cdn(ri["headers"], ri["final_url"])
            if ic:
                kv("  segment CDN", ", ".join(n for n, _ in ic))
        elif ri["error"]:
            kv("  error", C.red(ri["error"]))
    if seg_url and not single:
        kv("Media segment", short_url(seg_url))
        rs = fetch_media(seg_url, args, target.get("seg_range"))
        if rs["body"]:
            blobs.append(rs["body"])
            kv("  fetched", "%d bytes (HTTP %s)" % (len(rs["body"]), rs["status"]))
        elif rs["error"]:
            kv("  error", C.red(rs["error"]))

    if not blobs:
        print(C.yellow("  No media bytes retrieved (auth/geo/range may be blocked)."))
        return

    data = b"".join(blobs)
    ext = target.get("ext") or ".m4s"

    # --- MP4 box walk ---
    if not (data[:1] and data[0] == 0x47 and len(data) > 188 and data[188] == 0x47):
        f = walk_mp4(data)
    else:
        f = {"is_ts": True}

    print()
    if f.get("is_ts"):
        print("  " + C.bold("Container: ") + "MPEG-2 Transport Stream (.ts)")
        kv("  Packaging", "TS segments — older HLS / appliance packager")
    else:
        print("  " + C.bold("Container: ") + "fragmented MP4 / CMAF")
        if f.get("brands"):
            kv("  ftyp brands", " ".join(f["brands"]))
            cmaf = any(b in ("cmfc", "cmf2", "cmff") for b in f["brands"])
            kv("  CMAF", "yes" if cmaf else "not explicitly branded")
        if f.get("styp_brands"):
            kv("  styp brands", " ".join(f["styp_brands"]))
        if f.get("handlers"):
            for ht, name in f["handlers"]:
                if name:
                    kv("  hdlr (%s)" % ht, C.green(name) + C.dim("  <- muxer fingerprint"))
        if f.get("has_prft"):
            kv("  prft box", C.mag("present — low-latency producer reference time"))
        if f.get("has_sidx"):
            kv("  sidx box", "present (on-demand index)")
        # DRM from boxes
        if f.get("pssh"):
            for sid in f["pssh"]:
                name = DRM_SYSTEMS.get(sid.lower(), "Unknown DRM")
                kv("  pssh system", "%s  %s" % (C.green(name), C.dim(sid)))
        if f.get("schm"):
            schemes = {"cenc": "AES-CTR (cenc)", "cbcs": "AES-CBC pattern (cbcs)",
                       "cbc1": "AES-CBC (cbc1)", "cens": "AES-CTR pattern (cens)"}
            kv("  encryption scheme", ", ".join(schemes.get(s, s) for s in f["schm"]))
        if f.get("tenc"):
            prot = any(p for p, _ in f["tenc"])
            kids = ", ".join(k for _, k in f["tenc"])
            kv("  tenc", ("encrypted" if prot else "clear") + ("  default_KID=" + kids if kids else ""))
        if not (f.get("pssh") or f.get("schm") or f.get("tenc")):
            kv("  encryption", "no DRM boxes in this segment (clear, or DRM only in manifest)")

    # --- encoder signature byte scan (works without ffmpeg) ---
    sigs = scan_encoder_sigs(data)
    print()
    print("  " + C.bold("Encoder / muxer signatures (raw byte scan):"))
    if sigs:
        for label, s in sigs:
            tag = C.green(label)
            print("    %s  %s" % (tag, C.dim(s if len(s) < 200 else s[:200] + "…")))
    else:
        print("    " + C.dim("none found (production pipelines often strip these)"))

    # --- ffprobe structured read ---
    print()
    if have_ffprobe():
        print("  " + C.bold("ffprobe:"))
        pj = ffprobe_bytes(data, ext)
        if pj and "streams" in pj:
            for st in pj["streams"]:
                ct = st.get("codec_type", "?")
                if ct == "video":
                    desc = "%s %s %s  %sx%s" % (
                        st.get("codec_name", "?"), st.get("profile", ""),
                        st.get("pix_fmt", ""), st.get("width", "?"), st.get("height", "?"))
                    fr = st.get("avg_frame_rate", "")
                    if fr and fr != "0/0":
                        try:
                            n, dd = fr.split("/")
                            desc += "  @%.3ffps" % (int(n) / int(dd)) if int(dd) else ""
                        except (ValueError, ZeroDivisionError):
                            pass
                    kv("    video", desc)
                    col = [st.get("color_primaries"), st.get("color_transfer"),
                           st.get("color_space")]
                    col = [c for c in col if c]
                    if col:
                        is_hdr = any(x in ("smpte2084", "arib-std-b67", "bt2020nc", "bt2020")
                                     for x in col)
                        kv("    colour", " / ".join(col) + ("  " + C.mag("← HDR") if is_hdr else ""))
                elif ct == "audio":
                    kv("    audio", "%s %s  %sHz %sch %s" % (
                        st.get("codec_name", "?"), st.get("profile", ""),
                        st.get("sample_rate", "?"), st.get("channels", "?"),
                        st.get("channel_layout", "")))
                elif ct in ("subtitle", "data"):
                    kv("    " + ct, st.get("codec_name", "?"))
            fmt = pj.get("format", {})
            if fmt.get("format_long_name"):
                kv("    format", fmt.get("format_long_name"))
        elif pj and pj.get("_stderr"):
            print("    " + C.dim("ffprobe: " + pj["_stderr"]))
        else:
            print("    " + C.dim("ffprobe produced no stream info (partial segment?)"))
    else:
        print("  " + C.yellow("ffprobe not on PATH — skipping structured codec read."))
        print("  " + C.dim("install ffmpeg for codec/HDR/frame-rate detail "
                           "(brew install ffmpeg / apt install ffmpeg)."))

    print()
    print(hr())
    print(C.dim("  Reminder: deep encoder identification is probabilistic when "
                "SEI strings are stripped."))


def short_url(u, n=78):
    if u and len(u) > n:
        return u[:n - 1] + "…"
    return u


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="ott-fingerprint.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Fingerprint the supply chain behind an HLS/DASH OTT stream "
                    "from its public manifest + a small segment sample.",
        epilog=textwrap.dedent("""\
            examples:
              python3 ott-fingerprint.py https://host/master.m3u8
              python3 ott-fingerprint.py https://host/stream.mpd --no-deep
              python3 ott-fingerprint.py https://host/master.m3u8 --variant highest
              python3 ott-fingerprint.py https://host/master.m3u8 --json > out.json

            ffprobe/ffmpeg are optional; install for codec/HDR detail.
            Only use on streams you are authorised to access.
        """))
    p.add_argument("url", help="master manifest URL (.m3u8 or .mpd)")
    p.add_argument("--no-deep", action="store_true",
                   help="stop after the manifest; download no media bytes")
    p.add_argument("--variant", choices=["lowest", "highest"], default="lowest",
                   help="which rendition to sample for the deep probe (default: lowest = fast)")
    p.add_argument("--max-bytes", type=int, default=1_500_000,
                   help="cap per-segment download size (default 1.5 MB)")
    p.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout seconds")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("--json", action="store_true",
                   help="emit a JSON report to stdout (after the human summary)")
    return p


def main(argv=None):
    import textwrap as _tw  # noqa - ensure available even if trimmed
    args = build_parser().parse_args(argv)
    C.enabled = sys.stdout.isatty() and not args.no_color
    if not re.match(r"^https?://", args.url):
        print("error: url must start with http:// or https://", file=sys.stderr)
        return 2
    try:
        report = run(args.url, args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    if args.json:
        print()
        print(json.dumps(report, indent=2, default=str))
    return 0


# textwrap is used in build_parser epilog
import textwrap  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
