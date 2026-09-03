# reconx

Correlate an in-scope IP list with subdomain-enumeration output, confirm each
FQDN still points into scope, then probe the survivors into a list of live URLs.

reconx is a single self-contained Python 3 script. It shells out to `dig`/`host`
for DNS and to ProjectDiscovery's **httpx** (the Go tool) for HTTP probing. It
has **no third-party Python dependencies** — everything it imports is standard
library.

---

## What it does

You give it two things:

- **`targets.txt`** — your authorization boundary: the IPs (and/or CIDR blocks)
  you're allowed to test, one per line.
- **a subdomain file** — output from subfinder / dnsx / similar. Lines like
  `name [A] [ip]`, `name [CNAME] [fqdn]`, `name,ip`, or bare names all parse.

reconx then:

1. **Correlates.** The IP list is the spine. A subdomain name is kept only when
   it resolves onto an in-scope IP; anything else is recorded as out-of-scope or
   unresolved, never silently dropped. PTR names for your IPs are gathered too.
2. **Gates on scope.** Right before writing, every candidate FQDN is re-resolved
   and kept only if a current A record is one of your target IPs. This catches
   DNS that drifted since enumeration. The gate is **on by default**
   (`--no-scope-check` disables it).
3. **Probes.** httpx probes the survivors and reports which schemes actually
   answered. `urls.txt` is authored entirely by httpx — every line is a URL that
   responded. No speculative `http://` + `https://` pairs, no guessing.

The guiding principle throughout: **nothing disappears silently.** Every name
that doesn't make it into `urls.txt` lands in a named file explaining why.

---

## Install

```bash
git clone https://github.com/<you>/reconx.git
cd reconx
chmod +x install.sh
./install.sh
```

`install.sh` checks for and (where it can) installs the three external
dependencies:

| Dependency | What it's for | Package |
|---|---|---|
| `dig` | DNS lookups | dnsutils / bind-utils / bind-tools |
| `host` | DNS lookups | (same package as dig) |
| **httpx** (Go) | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |

Python 3.6+ is required. No `pip install` step — there are no Python packages to
install.

### The httpx gotcha (read this)

On Kali/Debian, the bare command **`httpx` is often the Python HTTP library**, a
completely unrelated tool that will not work here. reconx wants ProjectDiscovery's
**Go** httpx. It looks, in order, for:

1. `~/go/bin/httpx` (where `go install` puts it)
2. a `httpx` on your PATH **verified** to be the real tool
3. `httpx-toolkit` (Kali's packaged name: `sudo apt install httpx-toolkit`)

If none is found, reconx falls back to a built-in raw-socket prober — usable, but
the Go tool gives materially better results. You can always point at a specific
binary with `--httpx-bin /path/to/httpx`.

---

## Usage

```bash
# typical run
python3 reconx.py -i targets.txt -s subs.txt -O out/ --resolve

# interactive: prompts for folders and picks files for you
python3 reconx.py

# correlation only, skip probing
python3 reconx.py -i targets.txt -s subs.txt -O out/ --no-probe

# offline: classify a previously captured httpx -json file
python3 reconx.py -i targets.txt -s subs.txt -O out/ --json-in httpx.jsonl
```

### Key options

| Flag | Meaning |
|---|---|
| `-i, --ips` | target IP/CIDR list (required) |
| `-s, --subs` | subdomain enumeration file |
| `-O, --outdir` | output folder (required) |
| `--resolve` | chase CNAME chains with dig that the subs file can't close itself |
| `--no-scope-check` | disable the write-time in-scope re-resolution gate (gate is ON by default) |
| `--no-probe` | correlation only; skip httpx |
| `--httpx-bin PATH` | point at a specific httpx binary |
| `--ports` | httpx port list (default covers 80/443 + common alt-HTTP ports) |
| `-j, --jobs` | parallel DNS workers (default 5; DNS is also globally rate-paced) |
| `--threads` | httpx threads (default 50) |

Run `python3 reconx.py --help` for the full list.

---

## Output files

All written into `-O`:

| File | Contents |
|---|---|
| **`urls.txt`** | The payoff. Live URLs httpx confirmed, one line per answering scheme. |
| `403.txt` | URLs that answered 403 (kept — a 403 means something's there). |
| `redirects.txt` | In-scope origins that redirect off-host (origin stays live; target logged). |
| `results.tsv` | IP-keyed table of every PTR name and matched subdomain. |
| `fqdns.txt` | Every in-scope FQDN found (what gets probed). |
| `no_http_response.txt` | In scope and resolved, but nothing answered on any probed port. |
| `unresolved.txt` | Lookup succeeded but returned no A record, or resolved only out of scope. |
| `lookup_failed.txt` | Lookup **timed out / errored** — unknown, not absent. **Retry these.** |
| `out-of-scope.txt` | Resolved, but to non-target IPs (with the IPs listed). |
| `rejected.txt` | Target IPs with no name at all. |
| `unreliable.txt` | IPs whose PTR lookup was inconclusive (not a confirmed absence). |
| `targets_expanded.txt` | If `targets.txt` had CIDR blocks, the expanded IP list. |

`unresolved.txt` vs `lookup_failed.txt` is the distinction that matters most: the
first is "the resolver said there's no record"; the second is "the resolver
didn't answer." A name in `lookup_failed.txt` is almost always a transient hiccup
worth re-running, **not** a dead target.

---

## Notes on behaviour

**CIDR in targets.txt.** Blocks like `10.0.0.0/24` are expanded to individual
host IPs and used for all matching; the expanded set is written to
`targets_expanded.txt`. Blocks larger than 65,536 addresses (`/16` for IPv4) are
refused rather than exhausting memory — narrow the block if you truly need it.
IPv6 is not currently supported.

**DNS pacing.** Public resolvers (Google 8.8.8.8, Cloudflare 1.1.1.1) rate-limit
per client IP, and the failure mode is *bursts*, not total volume. reconx paces
dig calls to a minimum ~0.15s apart globally (a few queries/sec, well under
limits) so no burst forms. If you still see timeouts, raise `DNS_MIN_INTERVAL`
near the top of the script; on a private resolver you can lower it.

**Virtual hosting.** If one IP serves many subdomains (common), httpx will report
a hit per subdomain on the shared ports — that's correct, not a false positive.
It counts FQDNs; a port scanner counts IPs, so the numbers legitimately differ.

**Scope safety.** The tool only ever *derives* scannable URLs from your IP list;
it never modifies `targets.txt`, and by default it won't emit a URL for a name it
can't re-confirm points into scope. Loosen this only deliberately, with
`--no-scope-check`.

---

## Disclaimer

reconx is for authorized security testing only. You are responsible for ensuring
you have permission to test everything in `targets.txt`. The scope gate is a
safety aid, not a substitute for a signed authorization.
