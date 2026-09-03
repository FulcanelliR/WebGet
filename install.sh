#!/usr/bin/env bash
#
# install.sh - dependency setup for WebGet
#
# WebGet itself is a single self-contained Python 3 script with NO third-party
# Python packages (everything it imports is in the standard library). What it
# DOES need is three external programs on your PATH:
#
#   1. dig   - DNS lookups            (package: dnsutils / bind-utils / bind-tools)
#   2. host  - DNS lookups            (usually same package as dig)
#   3. httpx - ProjectDiscovery's Go HTTP prober   (NOT the Python 'httpx' lib!)
#
# The httpx gotcha: on Kali/Debian the bare name 'httpx' is often the Python
# HTTP *library*, which is a completely different thing and will not work.
# WebGet looks for the real Go tool at ~/go/bin/httpx, then a verified 'httpx'
# on PATH, then 'httpx-toolkit'. This script installs the Go tool to ~/go/bin.
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# The script is idempotent: re-running it just re-checks and skips what's present.

set -euo pipefail

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[0;33m'; NC=$'\033[0m'
ok()   { echo "${GRN}[ok]${NC}   $*"; }
warn() { echo "${YEL}[warn]${NC} $*"; }
err()  { echo "${RED}[err]${NC}  $*" >&2; }
info() { echo "[..]   $*"; }

# --- detect package manager (best-effort; used only for dig/host) ------------
PKG=""
if   command -v apt-get >/dev/null 2>&1; then PKG="apt"
elif command -v dnf     >/dev/null 2>&1; then PKG="dnf"
elif command -v yum     >/dev/null 2>&1; then PKG="yum"
elif command -v pacman  >/dev/null 2>&1; then PKG="pacman"
elif command -v brew    >/dev/null 2>&1; then PKG="brew"
fi

install_dnsutils() {
  case "$PKG" in
    apt)    sudo apt-get update -qq && sudo apt-get install -y dnsutils ;;
    dnf)    sudo dnf install -y bind-utils ;;
    yum)    sudo yum install -y bind-utils ;;
    pacman) sudo pacman -S --needed --noconfirm bind ;;
    brew)   brew install bind ;;
    *)      err "Unknown package manager. Install 'dig' and 'host' manually "
            err "(they ship in dnsutils / bind-utils / bind-tools)."; return 1 ;;
  esac
}

# --- 1 & 2: dig and host -----------------------------------------------------
echo "=== checking DNS tools (dig, host) ==="
NEED_DNS=0
command -v dig  >/dev/null 2>&1 && ok "dig found: $(command -v dig)"   || { warn "dig not found";  NEED_DNS=1; }
command -v host >/dev/null 2>&1 && ok "host found: $(command -v host)" || { warn "host not found"; NEED_DNS=1; }
if [ "$NEED_DNS" -eq 1 ]; then
  info "installing DNS utilities..."
  install_dnsutils && ok "DNS tools installed" || err "could not install DNS tools automatically"
fi

# --- 3: ProjectDiscovery httpx (Go) ------------------------------------------
echo
echo "=== checking ProjectDiscovery httpx (Go) ==="

is_pd_httpx() {
  # The real tool prints a 'projectdiscovery' banner for -version; the Python
  # library errors on the flag. This mirrors WebGet's own detection.
  "$1" -version 2>&1 | grep -qi "projectdiscovery"
}

HTTPX_OK=0
if [ -x "$HOME/go/bin/httpx" ] && is_pd_httpx "$HOME/go/bin/httpx"; then
  ok "real httpx found: $HOME/go/bin/httpx"; HTTPX_OK=1
elif command -v httpx >/dev/null 2>&1 && is_pd_httpx "$(command -v httpx)"; then
  ok "real httpx found on PATH: $(command -v httpx)"; HTTPX_OK=1
elif command -v httpx-toolkit >/dev/null 2>&1; then
  ok "httpx-toolkit found: $(command -v httpx-toolkit)"; HTTPX_OK=1
fi

if [ "$HTTPX_OK" -eq 0 ]; then
  warn "no real ProjectDiscovery httpx found."
  if command -v go >/dev/null 2>&1; then
    info "installing via 'go install' (this can take a minute)..."
    GO111MODULE=on go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    if [ -x "$HOME/go/bin/httpx" ] && is_pd_httpx "$HOME/go/bin/httpx"; then
      ok "httpx installed to $HOME/go/bin/httpx"
      case ":$PATH:" in
        *":$HOME/go/bin:"*) : ;;
        *) warn "Add Go bin to your PATH so WebGet (and you) can find it:"
           echo "      echo 'export PATH=\"\$PATH:\$HOME/go/bin\"' >> ~/.bashrc && source ~/.bashrc" ;;
      esac
    else
      err "go install ran but the binary isn't where expected (~/go/bin/httpx)."
      err "Check 'go env GOPATH' and add its /bin to PATH."
    fi
  else
    err "Go toolchain not found, so httpx can't be auto-installed."
    err "Either:"
    err "  - install Go, then re-run this script, OR"
    err "  - on Kali:  sudo apt install httpx-toolkit, OR"
    err "  - grab a release binary from https://github.com/projectdiscovery/httpx/releases"
    err "WebGet will fall back to its built-in socket prober if httpx is absent,"
    err "but the Go tool gives much better results."
  fi
fi

# --- Python sanity -----------------------------------------------------------
echo
echo "=== checking Python ==="
if command -v python3 >/dev/null 2>&1; then
  PYV="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
  ok "python3 found: $PYV (WebGet needs 3.6+; no pip packages required)"
else
  err "python3 not found. Install Python 3.6 or newer."
fi

echo
ok "setup check complete. Run WebGet with:  python3 webget.py -i ips.txt -s subs.txt -O out/ --resolve"
echo "   (or just 'python3 webget.py' with no args for interactive mode)"
