#!/usr/bin/env python3
"""
reconx.py - one-file recon tool.
Correlate a scope IP list with subfinder output, then turn every in-scope FQDN
into testable URLs.

urls.txt policy (this is the important part):
    A name that RESOLVES gets its base URLs (https:// and http://) written to
    urls.txt, unconditionally. Nothing httpx reports can remove a name from
    urls.txt. httpx runs every time and only ADDS to the list: it confirms
    served schemes and surfaces non-standard ports (http://host:8080, etc.).
    - Redirecting host: origin is alive, so its URL STAYS in urls.txt; the
      redirect target is logged to redirects.txt as informational only.
    - 403 host: something is answering, so its URL STAYS in urls.txt; the URL is
      ALSO recorded in 403.txt as extra signal.
    Resolution puts you in urls.txt. httpx can only enrich, never subtract.

    python3 reconx.py -i ips.txt -s subs.txt -O out/ --resolve
    python3 reconx.py                      # interactive folder prompts
    python3 reconx.py -i ips.txt -s subs.txt -O out/ --no-probe
    python3 reconx.py ... --json-in httpx.jsonl   # offline: parse captured httpx json
Outputs (in -O folder): results.tsv, fqdns.txt, urls.txt, 403.txt,
redirects.txt, rejected.txt, unreliable.txt, dead.txt
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from collections import defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor
__version__ = "0.2.0"
# ===== from dns.py =====
"""DNS layer: reverse lookups, forward A-record resolution, CNAME chasing.
Every shell-out is retried and every failure is distinguishable from a genuine
'no record' answer, so a timeout is never silently reclassified as absence.

Public resolvers (Google 8.8.8.8, Cloudflare 1.1.1.1) rate-limit per client IP.
Google's hard ceiling is ~100 QPS, but that's an ISP-scale limit; Google's own
guidance treats a few QPS from a single client as the comfortable sustained
rate. The failure mode that bit us was BURSTINESS: 10 dig calls firing at once
looks like abuse and the resolver drops some, which then timed out and (via a
bug in a_lookup) got recorded as 'no records'. So we (a) cap concurrency, and
(b) space out dig calls with a global minimum interval, well under Google's
ceiling, so no burst ever forms.
"""
import threading
DIG_TIMEOUT = 5
MAX_CNAME_DEPTH = 10
BRACKET = re.compile(r"\[([^\]]+)\]")
# Global DNS pacing. DNS_MIN_INTERVAL is the minimum wall-clock gap between the
# START of consecutive dig invocations, enforced across all threads. 0.15s => a
# ceiling of ~6-7 dig calls/sec total regardless of --jobs, comfortably under
# public-resolver limits while staying fast enough for typical recon run sizes.
# Raise it (e.g. 0.25) if you still see drops; lower it on a private resolver.
DNS_MIN_INTERVAL = 0.15
_dns_gate_lock = threading.Lock()
_dns_last_call = [0.0]
def _dns_pace():
    """Block until at least DNS_MIN_INTERVAL has passed since the last dig start.
    Serializes only the tiny scheduling decision, not the lookup itself, so
    concurrency still helps - it just can't burst."""
    with _dns_gate_lock:
        now = time.monotonic()
        wait = DNS_MIN_INTERVAL - (now - _dns_last_call[0])
        if wait > 0:
            time.sleep(wait)
        _dns_last_call[0] = time.monotonic()
def run(cmd, retries=2, backoff=0.5):
    """Run a command, retrying on timeout. Returns (stdout, ok).
    ok=True means the command completed (rc 0), whether or not it produced
    output - an empty answer from a completed dig is a real 'no record', not a
    failure. ok=False means the command never completed cleanly (timeout,
    missing binary), i.e. the answer is unknown and must not be read as absence.
    """
    for attempt in range(retries + 1):
        try:
            _dns_pace()
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=DIG_TIMEOUT)
            if r.returncode == 0:
                return r.stdout, True
        except subprocess.TimeoutExpired:
            pass
        except (FileNotFoundError, OSError):
            return "", False
        if attempt < retries:
            time.sleep(backoff * (2 ** attempt))
    return "", False
def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
def norm(name):
    return name.strip().rstrip(".").lower()
def has_no_ptr(ip):
    """True only if the resolver positively says the record is absent.
    NXDOMAIN is absence. NOERROR is absence ONLY when the answer section is
    empty (ANSWER: 0); a NOERROR with answers means the record exists.
    Anything else (SERVFAIL/REFUSED/timeout) is unknown -> None."""
    out, ok = run(["dig", "+noall", "+comments", "-x", ip])
    if not ok:
        return None
    if "status: NXDOMAIN" in out:
        return True
    if "status: NOERROR" in out:
        m = re.search(r"ANSWER:\s*(\d+)", out)
        if m and int(m.group(1)) == 0:
            return True
        return None                   # NOERROR with answers = record exists
    return None                       # SERVFAIL / REFUSED / unknown
def ptr_lookup(ip):
    """-> (ip, names, confident). confident=False means the lookup was unreliable."""
    names, seen = [], set()
    dig_out, dig_ok = run(["dig", "+short", "-x", ip])
    for line in dig_out.splitlines():
        n = norm(line)
        if n and n not in seen:
            seen.add(n); names.append(n)
    host_out, host_ok = run(["host", ip])
    for line in host_out.splitlines():
        if "domain name pointer" in line:
            n = norm(line.rsplit("domain name pointer", 1)[1])
            if n and n not in seen:
                seen.add(n); names.append(n)
    if names:
        return ip, names, True
    return ip, [], bool(has_no_ptr(ip)) and (dig_ok or host_ok)
def a_lookup_status(name):
    """-> (ips, ok). ok=False means the lookup itself failed (timeout/error),
    which is NOT the same as 'resolved to no records'. Callers deciding scope
    must distinguish these: a failed lookup is 'unknown', not 'absent'."""
    out, ok = run(["dig", "+short", name])
    ips = [l.strip() for l in out.splitlines() if is_ip(l.strip())]
    return ips, ok
def a_lookup(name):
    ips, _ = a_lookup_status(name)
    return ips
def resolve_chain(name, idx, do_dig, cache, depth=0, seen=None):
    """Follow CNAMEs (in-file first, dig as fallback) down to a set of IPs."""
    if name in cache:
        return cache[name]
    seen = seen or set()
    if depth > MAX_CNAME_DEPTH or name in seen:
        return set()
    seen.add(name)
    ips = set()
    for t in idx.get(name, []):
        if is_ip(t):
            ips.add(t)
        else:
            ips |= resolve_chain(t, idx, do_dig, cache, depth + 1, seen)
    if not ips and do_dig:
        ips = set(a_lookup(name))
    cache[name] = ips
    return ips
def name_resolves(name, do_dig):
    """True if a bare forward lookup of this FQDN returns at least one A record.
    Used to gate urls.txt: resolution is the only requirement to be listed."""
    return bool(a_lookup(name)) if do_dig else True
# ===== from correlate.py =====
"""Correlation: parse inputs, join subfinder names to the in-scope IP list.
The IP list is the spine. A subfinder name contributes only when its resolved
IP is in that list; anything else is recorded as out-of-scope or unresolved,
never silently dropped.
"""
def parse_subs(path):
    """Handles 'name [A] [ip]', 'name [CNAME] [fqdn]', 'name,ip', and bare names."""
    records = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = BRACKET.findall(line)
            if fields:
                name = norm(line.split("[", 1)[0])
                targets = [norm(t) for t in (fields if is_ip(fields[0].strip())
                                             else fields[1:])]
            elif "," in line:
                parts = [p.strip() for p in line.split(",")]
                name, targets = norm(parts[0]), [norm(p) for p in parts[1:]]
            else:
                name, targets = norm(line.split()[0]), []
            if name:
                records.append((name, [t for t in targets if t]))
    return records
MAX_CIDR_HOSTS = 65536   # per-block expansion cap (/16 for IPv4); refuse bigger

def read_ips(path):
    """Read targets.txt into a flat list of individual IP strings.
    A line may be a bare IP or a CIDR block (10.0.0.0/24). CIDR blocks are
    expanded into their individual host addresses so every downstream membership
    check ('does this A record hit a target?') is a simple exact match. Blocks
    larger than MAX_CIDR_HOSTS are refused with a clear error rather than
    exhausting memory. Order is preserved; duplicates are dropped.
    Returns (ips, expanded_from_cidr) where expanded_from_cidr is True if any
    line was a CIDR block (so the caller can write the expanded artifact)."""
    ips, seen = [], set()
    expanded_from_cidr = False
    with open(path) as fh:
        for lineno, raw in enumerate(fh, 1):
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            if "/" in entry:
                # CIDR block -> expand to host addresses.
                try:
                    net = ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    sys.exit(f"targets.txt line {lineno}: '{entry}' is not a valid "
                             f"IP or CIDR block.")
                count = net.num_addresses
                if count > MAX_CIDR_HOSTS:
                    sys.exit(f"targets.txt line {lineno}: {entry} expands to {count} "
                             f"addresses, over the {MAX_CIDR_HOSTS} cap. Narrow the "
                             f"block (or raise MAX_CIDR_HOSTS if you truly mean it).")
                expanded_from_cidr = True
                # .hosts() drops network/broadcast for real subnets; for /31 and
                # /32 it yields the usable address(es) as-is.
                members = list(net.hosts()) or [net.network_address]
                for addr in members:
                    s = str(addr)
                    if s not in seen:
                        seen.add(s); ips.append(s)
            else:
                if entry not in seen:
                    seen.add(entry); ips.append(entry)
    return ips, expanded_from_cidr
def correlate(ips, subs_path, do_dig, jobs):
    """-> (ptrs, ip_to_subs, unmatched, shaky).
    ptrs         : ip -> [ptr names]
    ip_to_subs   : ip -> [subfinder names that resolved onto it]
    unmatched    : [(kind, name, [resolved ips])]  kind in {out-of-scope, unresolved}
    shaky        : [ip]  PTR lookup was unreliable (not a confirmed absence)
    """
    ipset = set(ips)
    ip_to_subs = defaultdict(list)
    unmatched = []
    if subs_path:
        records = parse_subs(subs_path)
        idx = defaultdict(list)
        for name, targets in records:
            idx[name].extend(targets)
        cache = {}
        for name in dict.fromkeys(n for n, _ in records):
            hits = resolve_chain(name, idx, do_dig, cache)
            matched = hits & ipset
            for ip in matched:
                ip_to_subs[ip].append(name)
            if not matched:
                unmatched.append(("out-of-scope" if hits else "unresolved",
                                  name, sorted(hits)))
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        results = list(pool.map(ptr_lookup, ips))
    ptrs = {ip: names for ip, names, _ in results}
    shaky = [ip for ip, names, confident in results if not names and not confident]
    return ptrs, ip_to_subs, unmatched, shaky
def all_fqdns(ips, ptrs, ip_to_subs):
    """Deduped set of every in-scope FQDN found, from PTRs and matched subs."""
    return sorted({n for ip in ips for n in ptrs.get(ip, [])} |
                  {n for subs in ip_to_subs.values() for n in subs})
# ===== from probe.py =====
"""URL probing. Primary path: ProjectDiscovery httpx (Go). Fallback: raw sockets.

urls.txt is authored by httpx - every line is a URL that actually answered:
  * The in-scope gate (build_baseline_urls) decides which FQDNs are eligible:
    a name must re-resolve to an IP in targets.txt. It emits NO speculative URLs.
  * httpx then probes the standard web ports and reports the scheme(s) that
    answered. Only those confirmed URLs go to urls.txt - no http/https guessing,
    no port-suffixed copies.
  * Redirecting origin -> origin URL is live; redirect target logged to
    redirects.txt.
  * 403 -> confirmed answer, so its URL is in urls.txt and also in 403.txt.
  * In-scope names httpx could not confirm on any probed scheme are recorded in
    no_http_response.txt (visible, not silently dropped) rather than urls.txt.
Every probe result is a Result(host, url, code, note).
"""
Result = namedtuple("Result", "host url code note")
# Standard web ports only. reconx's job is base URLs (https://host, http://host);
# non-standard ports (8080/8443/etc.) are the rare case and were cluttering
# urls.txt with :port copies of every host, so we don't probe them by default.
# Pass --ports to widen if a specific engagement needs nonstandard ports.
DEFAULT_PORTS = "80,443,8080,8443,8000,8008,8888,3000,5000,7001,9000,9090,81,4443,9443"
# fallback socket prober: (port, scheme), TLS-capable first so https wins.
# Standard ports only, matching DEFAULT_PORTS - the fallback should produce the
# same bare base URLs httpx does, never :port-suffixed ones.
_FALLBACK_PORTS = [
    (443, "https"),
    (80, "http"),
]
SOCKET_TIMEOUT = 6
# ---------- shared scope helpers ----------
def canon_host(host):
    """www.domain.com and domain.com are the same host. api. and office. are not."""
    h = (host or "").lower().strip().rstrip(".")
    return h[4:] if h.startswith("www.") else h
def url_parts(url):
    m = re.match(r"(https?)://([^/:?#]+)(?::(\d+))?", url or "", re.I)
    if not m:
        return "", "", None
    return m.group(1).lower(), m.group(2).lower(), (int(m.group(3)) if m.group(3) else None)
def origin_url(scheme, host, port):
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"
def build_baseline_urls(fqdns, run_gate, jobs, ipset=None):
    """The write-time in-scope resolution gate.
    Each FQDN is re-resolved (forward A lookup) and kept ONLY if at least one of
    its CURRENT A records is an IP in targets.txt (ipset). This is the
    authorization boundary: a name is eligible for urls.txt only if it still
    points into scope at write time, catching DNS that drifted since correlation
    and subfinder names that matched via a stale CNAME.
    NOTE: this function no longer emits speculative URLs. It used to add BOTH
    https:// and http:// for every in-scope name; that doubled every host in
    urls.txt and asserted schemes that may not answer. Now httpx is the sole
    author of urls.txt - a host gets a line only for the scheme(s) httpx actually
    confirmed. This function just decides who is in scope; the caller unions the
    confirmed URLs. In-scope names httpx could NOT confirm are recorded
    separately (no_http_response) so nothing is silently dropped.
    Returns (in_scope, out_of_scope, unresolved, lookup_failed):
      in_scope      : [name]              resolved to >=1 target IP  (eligible)
      out_of_scope  : [(name, [ips])]     resolved, but to NO target IP (held back)
      unresolved    : [name]              lookup succeeded, NO A record (real absence)
      lookup_failed : [name]              lookup timed out/errored (UNKNOWN, retryable)
    lookup_failed is the key fix: a name whose dig timed out under load is no
    longer misfiled as unresolved. It's a distinct 'we could not determine'
    bucket, so a transient resolver hiccup never asserts a real host is absent.
    run_gate is the master switch (driven by --no-scope-check, default ON). When
    False we trust correlation and treat every FQDN as in-scope."""
    ipset = set(ipset or ())
    def classify(name):
        recs_list, ok = a_lookup_status(name)
        if not ok:
            return name, "lookup_failed", set()
        recs = set(recs_list)
        if not recs:
            return name, "unresolved", set()
        if recs & ipset:
            return name, "in_scope", recs
        return name, "out_of_scope", recs
    in_scope, out_of_scope, unresolved, lookup_failed = [], [], [], []
    if run_gate:
        with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            verdicts = list(pool.map(classify, fqdns))
        for name, verdict, recs in verdicts:
            if verdict == "in_scope":
                in_scope.append(name)
            elif verdict == "out_of_scope":
                out_of_scope.append((name, sorted(recs)))
            elif verdict == "lookup_failed":
                lookup_failed.append(name)
            else:
                unresolved.append(name)
    else:
        # No re-resolution: trust correlation, treat every FQDN as in-scope.
        in_scope = list(fqdns)
    return in_scope, out_of_scope, unresolved, lookup_failed
def resolve_httpx_bin(explicit=None):
    """Find the REAL ProjectDiscovery httpx (Go) binary.
    Preference order, real Go tool first:
      1. explicit --httpx-bin path (honored as given)
      2. ~/go/bin/httpx        (the standard go-install location)
      3. bare 'httpx' on PATH, but ONLY if verified as the PD tool (on Kali the
         bare name can be the Python library, which we must never use)
      4. httpx-toolkit         (last resort; often an older/repackaged build)
    Returns the binary name/path, or None if no real one is found.
    """
    if explicit:
        return explicit if (shutil.which(explicit) or os.path.isfile(explicit)) else None
    go_bin = os.path.expanduser("~/go/bin/httpx")
    if os.path.isfile(go_bin) and _is_projectdiscovery_httpx(go_bin):
        return go_bin
    if shutil.which("httpx") and _is_projectdiscovery_httpx("httpx"):
        return "httpx"
    if shutil.which("httpx-toolkit") and _is_projectdiscovery_httpx("httpx-toolkit"):
        return "httpx-toolkit"
    return None
# ---------- primary path: httpx ----------
def _httpx_cmd(binary, list_path, ports, threads, timeout, retries, rate):
    cmd = [binary, "-l", list_path, "-json", "-silent", "-nc",
           "-sc", "-location", "-title", "-fr",
           "-ports", ports, "-threads", str(threads),
           "-timeout", str(timeout), "-retries", str(retries)]
    if rate:
        cmd += ["-rate-limit", str(rate)]
    return cmd
def _iter_json(lines):
    for line in lines:
        line = line.strip()
        if line:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
def _rec_field(rec, *keys):
    """First present, non-empty value among keys (handles httpx version drift in
    field naming: status_code vs status-code, final_url vs final-url, etc.)."""
    for k in keys:
        v = rec.get(k)
        if v not in (None, ""):
            return v
    return None
def _classify(rec):
    """One httpx JSON record -> Result (enrichment signal).
    We read the served URL, its status code, and any redirect target. This is
    used only to ADD port/scheme variants and to populate 403.txt/redirects.txt;
    it can never remove a baseline URL."""
    asked = _rec_field(rec, "input", "host") or ""
    asked_host = canon_host(re.sub(r"^https?://", "", str(asked)).split(":")[0].split("/")[0])
    url = _rec_field(rec, "url") or ""
    scheme, host, port = url_parts(url)
    if not host:
        return None
    code = str(_rec_field(rec, "status_code", "status-code") or "")
    final = _rec_field(rec, "final_url", "final-url", "location") or url
    _, fhost, _ = url_parts(final if re.match(r"https?://", str(final) or "") else url)
    fhost = fhost or host
    origin = origin_url(scheme, host, port)
    ref = asked_host or host
    if canon_host(fhost) != canon_host(ref):
        return Result(ref, origin, code, f"redirects to {final}")
    return Result(ref, origin, code, "")
def _is_projectdiscovery_httpx(binary="httpx"):
    """The Python 'httpx' (Kali default at /usr/bin/httpx) shadows the real tool.
    Tell them apart by the -version banner: the PD (Go) tool identifies itself as
    projectdiscovery; the Python library errors on the flag. We require the
    'projectdiscovery' string specifically - a bare version number is NOT enough,
    because unrelated tools also print version numbers."""
    try:
        r = subprocess.run([binary, "-version"], capture_output=True, text=True, timeout=10)
        blob = (r.stdout + r.stderr).lower()
        return "projectdiscovery" in blob
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False
def probe_with_httpx(list_path, ports, threads, timeout, retries, rate, binary):
    if not os.path.isfile(list_path):
        raise RuntimeError(f"FQDN list not found at {list_path} (reconx should have "
                           f"written it - this is a bug, not your input)")
    if os.path.getsize(list_path) == 0:
        raise RuntimeError(f"FQDN list {list_path} is empty - no in-scope FQDNs were "
                           f"found to probe, so there is nothing for httpx to do")
    cmd = _httpx_cmd(binary, list_path, ports, threads, timeout, retries, rate)
    print("running: " + " ".join(cmd), file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"{binary} exited {proc.returncode}. Its stderr was:\n"
                           f"{proc.stderr.strip() or '(no stderr)'}")
    out = []
    for rec in _iter_json(proc.stdout.splitlines()):
        r = _classify(rec)
        if r:
            out.append(r)
    return out
def parse_httpx_json(path):
    """For offline testing: build Results from a captured httpx -json file."""
    out = []
    with open(path) as fh:
        for rec in _iter_json(fh):
            r = _classify(rec)
            if r:
                out.append(r)
    return out
# ---------- fallback path: raw sockets ----------
#
# A completed TCP connect is NOT proof of a web service: firewalls, load
# balancers and IPS devices routinely accept connections on ports nothing
# serves (SYN-proxying). So we connect AND require a valid HTTP response line
# before calling a port open.
def _tcp_connect(host, port, timeout):
    try:
        return socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
def _read_status_line(sock, timeout):
    """Read until we have at least the status line or the peer closes. Returns
    the first chunk of bytes (may span several recvs)."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < 16 and b"\n" not in buf:
            chunk = sock.recv(64)
            if not chunk:
                break
            buf += chunk
    except OSError:
        return buf
    return buf
def _speaks_http_plain(sock, host, timeout):
    """Send a minimal HTTP/1.1 request; True if a valid HTTP status line comes
    back. Reads iteratively so a short first recv doesn't cause a false negative."""
    try:
        sock.settimeout(timeout)
        req = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: reconx\r\nConnection: close\r\n\r\n").encode()
        sock.sendall(req)
    except OSError:
        return False
    data = _read_status_line(sock, timeout)
    return data[:5] == b"HTTP/"
def _speaks_http_tls(host, port, timeout):
    """Wrap the socket in TLS (cert validation OFF, like curl -k) and probe HTTP.
    A handshake failure is not fatal to the host - another port/scheme may still
    answer. wrap_socket owns the underlying socket, so the 'with' closes it; we
    do not double-close."""
    raw = _tcp_connect(host, port, timeout)
    if raw is None:
        return False
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return _speaks_http_plain(tls, host, timeout)
    except (ssl.SSLError, OSError):
        try:
            raw.close()
        except OSError:
            pass
        return False
def _port_serves_web(host, port, scheme, timeout=SOCKET_TIMEOUT):
    if scheme == "https":
        return _speaks_http_tls(host, port, timeout)
    sock = _tcp_connect(host, port, timeout)
    if sock is None:
        return False
    try:
        return _speaks_http_plain(sock, host, timeout)
    finally:
        try:
            sock.close()
        except OSError:
            pass
def _probe_socket_all(host, ports):
    """Return every (scheme, port) on this host that answers HTTP - not just the
    first. Enrichment wants all served endpoints, not one."""
    found = []
    for port, scheme in ports:
        if _port_serves_web(host, port, scheme):
            found.append(Result(canon_host(host), origin_url(scheme, host, port),
                                "", f"open:{port}"))
    return found or [Result(canon_host(host), None, "", "no open web port")]
def probe_with_sockets(hosts, jobs):
    results = []
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for group in pool.map(lambda h: _probe_socket_all(h, _FALLBACK_PORTS), hosts):
            results.extend(group)
    return results
# ===== from output.py =====
"""All file writing lives here, so the set of outputs is easy to see and change."""
def write_results_tsv(path, ips, ptrs, ip_to_subs, tag, marker, keep_empty):
    """IP-keyed table. Returns (dead_ips, matched_row_count)."""
    dead, matched = [], 0
    with open(path, "w") as fh:
        for ip in ips:
            cols, seen = [], set()
            for n in ptrs.get(ip, []):
                if n not in seen:
                    seen.add(n); cols.append(f"ptr={n}" if tag else n)
            subs = sorted(set(ip_to_subs.get(ip, [])))
            if subs:
                matched += 1
            for n in subs:
                if n not in seen:
                    seen.add(n); cols.append(f"sub={n}" if tag else n)
            if not cols:
                dead.append(ip)
                if not keep_empty:
                    continue
            fh.write(ip + "\t" + "\t".join(cols or [marker]) + "\n")
    return dead, matched
def write_lines(path, lines):
    with open(path, "w") as fh:
        for line in lines:
            fh.write(line + "\n")
def split_enrichment(results):
    """Partition httpx/socket Results into ADD-ONLY buckets.
    -> dict with keys: extra_urls, forbidden_urls, redirects
    NONE of these can remove a baseline URL; they only add.
      extra_urls     : served URLs httpx confirmed (incl. non-standard ports),
                       merged into urls.txt on top of the resolving-name floor.
                       A redirecting origin's URL is included here too (origin is
                       alive, we scan the source).
      forbidden_urls : 403 responders -> 403.txt (also kept in urls.txt).
      redirects      : (origin_url, note) -> redirects.txt, informational.
    """
    extra, forbidden, redirects = [], [], []
    for r in results:
        if r.url is None:
            continue                       # no served endpoint; baseline still has the name
        # The origin answered something, so its URL is a real live endpoint.
        extra.append(r.url)
        if r.note.startswith("redirects to "):
            redirects.append((r.url, r.note))
        if r.code == "403":
            forbidden.append(r.url)
    return {
        "extra_urls": sorted(set(extra)),
        "forbidden_urls": sorted(set(forbidden)),
        "redirects": sorted(set(redirects)),
    }
# ===== from cli.py =====
"""reconx CLI: correlate an IP list with subfinder output, then probe FQDNs to URLs."""
OUTPUT_NAMES = {
    "results": "results.tsv",
    "urls": "urls.txt",
    "rejected": "rejected.txt",
    "unreliable": "unreliable.txt",
    "forbidden": "403.txt",
    "redirects": "redirects.txt",
    "fqdns": "fqdns.txt",
    "unresolved": "unresolved.txt",
    "lookup_failed": "lookup_failed.txt",
    "no_http_response": "no_http_response.txt",
    "targets_expanded": "targets_expanded.txt",
    "out_of_scope": "out-of-scope.txt",
}
def _looks_like_ips(path, sample=20):
    hits = seen = 0
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                seen += 1
                if is_ip(line.split()[0].split(",")[0].strip("[]")):
                    hits += 1
                if seen >= sample:
                    break
    except OSError:
        return False
    return bool(seen) and hits / seen > 0.7
def _pick(prompt, candidates):
    if candidates:
        print(prompt)
        for i, c in enumerate(candidates, 1):
            print(f"  {i}) {os.path.basename(c)}")
        print("  0) enter a different path")
        while True:
            choice = input("  choice: ").strip()
            if choice == "0":
                break
            if choice.isdigit() and 1 <= int(choice) <= len(candidates):
                return candidates[int(choice) - 1]
            print("  ...pick a number from the list.")
    while True:
        path = os.path.expanduser(input(f"  {prompt} (full path): ").strip())
        if os.path.isfile(path):
            return path
        print(f"  ...no file at {path}")
def interactive():
    print(f"=== reconx {__version__} interactive setup ===")
    while True:
        in_dir = os.path.expanduser(input("Folder holding the IP list and subdomain file: ").strip())
        if os.path.isdir(in_dir):
            break
        print(f"  ...no folder at {in_dir}")
    files = [os.path.join(in_dir, f) for f in sorted(os.listdir(in_dir))
             if os.path.isfile(os.path.join(in_dir, f))]
    ip_guesses = [f for f in files if _looks_like_ips(f)]
    print("\n-- which file is the IP list?")
    ip_file = _pick("IP list", ip_guesses or files)
    print("\n-- which file is the subdomain (subfinder) list?")
    sub_file = _pick("subdomain list", [f for f in files if f != ip_file])
    while True:
        out_dir = os.path.expanduser(input("\nFolder to write outputs into: ").strip())
        try:
            os.makedirs(out_dir, exist_ok=True)
            break
        except OSError as e:
            print(f"  ...can't use that folder ({e})")
    j = input("Parallel DNS lookups [5]: ").strip()
    ns = argparse.Namespace(
        ips=ip_file, subs=sub_file, outdir=out_dir,
        jobs=int(j) if j.isdigit() else 5,
        resolve=True, tag=False, keep_empty=False, no_scope_check=False,
        marker="NO_PTR", ports=DEFAULT_PORTS, threads=50, timeout=10,
        retries=2, rate=0, no_probe=False, json_in=None, httpx_bin=None,
    )
    print(f"\nReading {os.path.basename(ip_file)} + {os.path.basename(sub_file)} "
          f"-> outputs into {out_dir}\n")
    return ns
def build_parser():
    p = argparse.ArgumentParser(prog="reconx",
                                description="Correlate IPs+subdomains, probe FQDNs to URLs (httpx-backed).")
    p.add_argument("-i", "--ips", help="IP list, one per line")
    p.add_argument("-s", "--subs", help="subfinder/dnsx output file")
    p.add_argument("-O", "--outdir", help="folder for all output files")
    p.add_argument("-j", "--jobs", type=int, default=5,
                   help="parallel DNS lookup workers (default: 5). DNS calls are "
                        "additionally rate-paced globally, so raising this won't "
                        "burst the resolver.")
    p.add_argument("--resolve", action="store_true",
                   help="dig CNAME chains the subfinder file can't close on its own")
    p.add_argument("--tag", action="store_true", help="prefix names ptr=/sub= in results.tsv")
    p.add_argument("--keep-empty", action="store_true",
                   help="keep no-name IPs in results.tsv (default: only in rejected.txt)")
    p.add_argument("--marker", default="NO_PTR", help="placeholder for empty rows if kept")
    p.add_argument("--no-scope-check", dest="no_scope_check", action="store_true",
                   help="skip the write-time in-scope re-resolution gate (default: "
                        "gate ON - a name is written only if it re-resolves to a "
                        "target IP)")
    # probing
    p.add_argument("--httpx-bin", dest="httpx_bin",
                   help="path/name of the ProjectDiscovery httpx binary "
                        "(default: auto-detect ~/go/bin/httpx, then PATH httpx)")
    p.add_argument("--no-probe", action="store_true",
                   help="scope-gate and list in-scope FQDNs only; skip httpx "
                        "(urls.txt is httpx-authored, so it will be empty)")
    p.add_argument("--ports", default=DEFAULT_PORTS, help=f"httpx -ports (default: {DEFAULT_PORTS})")
    p.add_argument("--threads", type=int, default=50, help="httpx threads (default: 50)")
    p.add_argument("--timeout", type=int, default=10, help="httpx timeout s (default: 10)")
    p.add_argument("--retries", type=int, default=2, help="httpx retries (default: 2)")
    p.add_argument("--rate", type=int, default=0, help="httpx rate-limit req/s (0=default)")
    p.add_argument("--json-in", dest="json_in",
                   help="parse a captured httpx -json file instead of probing live (testing)")
    return p
def run_pipeline(ns):
    out = lambda key: os.path.join(ns.outdir, OUTPUT_NAMES[key])
    os.makedirs(ns.outdir, exist_ok=True)
    ips, expanded_from_cidr = read_ips(ns.ips)
    if not ips:
        sys.exit("No IPs found in input.")
    if expanded_from_cidr:
        write_lines(out("targets_expanded"), ips)
        print(f"targets: expanded CIDR blocks -> {len(ips)} individual IPs "
              f"written to {out('targets_expanded')}", file=sys.stderr)
    ptrs, ip_to_subs, unmatched, shaky = correlate(ips, ns.subs, ns.resolve, ns.jobs)
    dead_ips, matched = write_results_tsv(
        out("results"), ips, ptrs, ip_to_subs, ns.tag, ns.marker, ns.keep_empty)
    write_lines(out("rejected"), dead_ips)
    write_lines(out("unreliable"), shaky)
    fqdns = all_fqdns(ips, ptrs, ip_to_subs)
    write_lines(out("fqdns"), fqdns)
    print(f"correlation: {len(ips)} IPs, {matched} enriched, {len(dead_ips)} rejected, "
          f"{len(unmatched)} subfinder entries out-of-scope/unresolved, "
          f"{len(fqdns)} FQDNs to probe", file=sys.stderr)
    # ---- in-scope gate: decide who is eligible for urls.txt ----
    # urls.txt is authored by httpx: a name gets a line only for the scheme(s)
    # httpx confirmed answered. No speculative http+https pair. Gate ON by
    # default; --no-scope-check turns it off.
    run_gate = not getattr(ns, "no_scope_check", False)
    in_scope_fqdns, out_of_scope, unresolved_fqdns, lookup_failed = build_baseline_urls(
        fqdns, run_gate, ns.jobs, ipset=set(ips))
    # Held-back names, deduped, in one place (unresolved.txt): names whose lookup
    # SUCCEEDED but returned no A record, plus names that resolved only outside
    # scope. out-of-scope names additionally get their IPs in out-of-scope.txt.
    held_back = sorted(set(unresolved_fqdns) | {n for n, _ in out_of_scope})
    write_lines(out("unresolved"), held_back)
    with open(out("out_of_scope"), "w") as fh:
        for name, recs in out_of_scope:
            fh.write(f"{name}\t{','.join(recs)}\n")
    # Names whose lookup FAILED (timeout/error) - unknown, not absent. Recorded
    # separately so a transient resolver hiccup is visible and retryable, never
    # silently asserted as out-of-scope/unresolved.
    write_lines(out("lookup_failed"), sorted(lookup_failed))
    if run_gate:
        print(f"scope gate: {len(in_scope_fqdns)} FQDNs in scope "
              f"({len(out_of_scope)} resolved out-of-scope, "
              f"{len(unresolved_fqdns)} resolved to no record, "
              f"{len(lookup_failed)} lookup FAILED/timed out -> "
              f"{out('lookup_failed')} (retry these))",
              file=sys.stderr)
    else:
        print(f"scope gate DISABLED (--no-scope-check): trusting correlation, "
              f"{len(in_scope_fqdns)} in-scope FQDNs.", file=sys.stderr)
    if ns.no_probe:
        # urls.txt is httpx-authored; with probing skipped there are no confirmed
        # schemes, so urls.txt cannot be produced. Emit the in-scope FQDN list so
        # the operator can probe later, and say so plainly.
        write_lines(out("urls"), [])
        write_lines(out("forbidden"), [])
        write_lines(out("redirects"), [])
        write_lines(out("no_http_response"), sorted(in_scope_fqdns))
        print(f"--no-probe: no scheme confirmation, so urls.txt is empty. "
              f"{len(in_scope_fqdns)} in-scope FQDNs -> {out('no_http_response')}; "
              f"run without --no-probe to author urls.txt.", file=sys.stderr)
        return
    # ---- httpx probing (sole author of urls.txt) ----
    explicit = getattr(ns, "httpx_bin", None)
    if ns.json_in:
        results = parse_httpx_json(ns.json_in)
        source = f"captured json ({ns.json_in})"
    else:
        binary = resolve_httpx_bin(explicit)
        if binary:
            try:
                results = probe_with_httpx(out("fqdns"), ns.ports, ns.threads,
                                           ns.timeout, ns.retries, ns.rate, binary)
                source = binary
            except RuntimeError as e:
                print(f"httpx error: {e}\nfalling back to socket prober", file=sys.stderr)
                results = probe_with_sockets(in_scope_fqdns or fqdns, ns.threads)
                source = "socket-fallback"
        else:
            print("no real ProjectDiscovery (Go) httpx found. Looked for "
                  "~/go/bin/httpx, then a verified 'httpx' on PATH, then "
                  "httpx-toolkit. Pass --httpx-bin <path> to point at your Go "
                  "build. Using socket fallback for this run.", file=sys.stderr)
            results = probe_with_sockets(in_scope_fqdns or fqdns, ns.threads)
            source = "socket-fallback"
    enrich = split_enrichment(results)
    # httpx ran against the full fqdns.txt, which still contains names the scope
    # gate rejected. Keep only findings whose host is in the in-scope set. Match
    # on canonical host (www-insensitive), the same key the gate uses.
    scope_hosts = {canon_host(n) for n in in_scope_fqdns}
    def in_scope_url(u):
        return canon_host(url_parts(u)[1]) in scope_hosts
    # A 403 is PROOF the host answered httpx. 403.txt is gated on the probed
    # universe (everything in fqdns.txt is correlation-anchored to targets, so a
    # 403 there is in-scope by construction), not the re-resolution gate which
    # can drop a real host on DNS drift.
    probed_hosts = {canon_host(n) for n in fqdns}
    def in_probed_universe(u):
        return canon_host(url_parts(u)[1]) in probed_hosts
    extra_in_scope = [u for u in enrich["extra_urls"] if in_scope_url(u)]
    forbidden_in_scope = [u for u in enrich["forbidden_urls"] if in_probed_universe(u)]
    redirects_in_scope = [(u, note) for (u, note) in enrich["redirects"] if in_scope_url(u)]
    # urls.txt = the schemes httpx actually confirmed (live findings + 403 origins).
    # No speculative URLs. Every line is a URL that answered.
    final_urls = sorted(set(extra_in_scope) | set(forbidden_in_scope))
    write_lines(out("urls"), final_urls)
    write_lines(out("forbidden"), sorted(set(forbidden_in_scope)))
    # In-scope names that httpx could NOT confirm on any probed scheme: not
    # dropped, recorded here so the coverage gap is visible.
    confirmed_hosts = {canon_host(url_parts(u)[1]) for u in final_urls}
    no_response = sorted(n for n in in_scope_fqdns
                         if canon_host(n) not in confirmed_hosts)
    write_lines(out("no_http_response"), no_response)
    with open(out("redirects"), "w") as fh:
        for url, note in redirects_in_scope:
            fh.write(f"{url}\t{note}\n")
    print(f"probing via {source}: urls.txt has {len(final_urls)} confirmed URLs "
          f"({len(set(forbidden_in_scope))} were 403, "
          f"{len(redirects_in_scope)} redirect off-host); "
          f"{len(no_response)} in-scope FQDNs got no HTTP response -> "
          f"{out('no_http_response')}; "
          f"{len(unresolved_fqdns)} did not resolve, "
          f"{len(out_of_scope)} resolved out-of-scope", file=sys.stderr)
def main():
    p = build_parser()
    if len(sys.argv) == 1 and sys.stdin.isatty():
        ns = interactive()
    else:
        ns = p.parse_args()
        if not (ns.ips and ns.outdir):
            p.error("need -i/--ips and -O/--outdir (or run with no args for interactive mode)")
    run_pipeline(ns)
if __name__ == "__main__":
    main()
