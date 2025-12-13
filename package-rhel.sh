#!/usr/bin/env bash
set -euo pipefail

# Use:
#   ./package-rhel.sh --version 0.0.1


die() { echo "ERROR: $*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

VERSION=""
RELEASE="1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"; shift 2;;
    --release)
      RELEASE="${2:-}"; shift 2;;
    -h|--help)
      cat <<EOF
Usage: $0 --version <x.y.z> [--release <n>]

Examples:
  $0 --version 0.0.1
  $0 --version 0.0.1 --release 2
EOF
      exit 0;;
    *)
      die "unknown arg: $1";;
  esac
done

[[ -n "$VERSION" ]] || die "missing --version, e.g. $0 --version 0.0.1"

if ! [[ "$VERSION" =~ ^[0-9]+(\.[0-9]+){1,3}([\-+][A-Za-z0-9\.\-_]+)?$ ]]; then
  die "invalid version format: $VERSION"
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[*] Requesting sudo..."
  sudo -v
  ( while true; do sleep 30; sudo -n true 2>/dev/null || exit; done ) &
  SUDO_KEEPALIVE_PID=$!
  trap 'kill "${SUDO_KEEPALIVE_PID:-0}" 2>/dev/null || true' EXIT
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

[[ -f "Cargo.toml" ]] || die "Cargo.toml not found in $ROOT_DIR"

echo "[*] Project root: $ROOT_DIR"
echo "[*] Version: $VERSION  Release: $RELEASE"

echo "[*] Installing build dependencies via dnf..."
sudo dnf -y makecache
sudo dnf -y install \
  git ca-certificates curl \
  gcc gcc-c++ make \
  pkgconf-pkg-config \
  openssl-devel \
  tar gzip findutils which \
  rpm-build rpmdevtools \
  systemd-rpm-macros \
  shadow-utils \
  || die "dnf install failed"

load_cargo_env() {
  local env1="${CARGO_HOME:-$HOME/.cargo}/env"
  local env2="$HOME/.cargo/env"
  if [[ -f "$env1" ]]; then
    source "$env1"
    return 0
  fi
  if [[ -f "$env2" ]]; then
    source "$env2"
    return 0
  fi
  return 1
}

if ! command -v cargo >/dev/null 2>&1; then
  echo "[*] Installing Rust (rustup) for current user..."
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  load_cargo_env || true
else
  load_cargo_env || true
fi
# -------------------------------------------------------------------------------

need_cmd cargo
need_cmd rustc
echo "[*] rustc: $(rustc -V)"
echo "[*] cargo: $(cargo -V)"

echo "[*] Building tg-guard (release)..."
cargo build --release

BIN="$ROOT_DIR/target/release/tg-guard"
[[ -f "$BIN" ]] || die "build succeeded but binary not found: $BIN"
chmod +x "$BIN"

RPMTOP="${HOME}/rpmbuild"
for d in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS; do
  mkdir -p "${RPMTOP}/${d}"
done

PKGNAME="tg-guard"
TOPBUILD="${RPMTOP}/BUILD/${PKGNAME}-${VERSION}"
rm -rf "$TOPBUILD"
mkdir -p "$TOPBUILD"

SERVICE_FILE="${TOPBUILD}/${PKGNAME}.service"
cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=tg-guard Telegram Guard Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tg-guard
Group=tg-guard
WorkingDirectory=/var/lib/tg-guard
ExecStart=/usr/bin/tg-guard --config /etc/tg-guard/config.yaml
Restart=always
RestartSec=3

# Hardening (safe defaults; adjust if you need more permissions)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

CFG_SRC=""
if [[ -f "$ROOT_DIR/config.example.yaml" ]]; then
  CFG_SRC="$ROOT_DIR/config.example.yaml"
elif [[ -f "$ROOT_DIR/config.yaml" ]]; then
  CFG_SRC="$ROOT_DIR/config.yaml"
fi

DEFAULT_CFG="${TOPBUILD}/config.yaml"
if [[ -n "$CFG_SRC" ]]; then
  cp -f "$CFG_SRC" "$DEFAULT_CFG"
else
  cat > "$DEFAULT_CFG" <<'EOF'
# tg-guard default config
bot:
  token: "REPLACE_ME"
  polling_timeout_secs: 25
  log_level: "info"

runtime:
  data_dir: "/var/lib/tg-guard"
  merge_group_notice: true
  merge_group_notice_max_names: 6
  merge_group_notice_interval_secs: 8
EOF
fi

cp -f "$BIN" "${TOPBUILD}/${PKGNAME}"
chmod 0755 "${TOPBUILD}/${PKGNAME}"

TARBALL="${RPMTOP}/SOURCES/${PKGNAME}-${VERSION}.tar.gz"
echo "[*] Creating source tarball: $TARBALL"
tar -C "${RPMTOP}/BUILD" -czf "$TARBALL" "${PKGNAME}-${VERSION}"

SPEC="${RPMTOP}/SPECS/${PKGNAME}.spec"
echo "[*] Generating spec: $SPEC"

DOC_FILES=()
for f in README README.md README.txt; do
  [[ -f "${TOPBUILD}/${f}" ]] && DOC_FILES+=("$f")
done

LIC_FILES=()
for f in LICENSE LICENSE.txt LICENSE.md COPYING NOTICE; do
  [[ -f "${TOPBUILD}/${f}" ]] && LIC_FILES+=("$f")
done

DOC_LINE=""
if [[ "${#DOC_FILES[@]}" -gt 0 ]]; then
  DOC_LINE="%doc ${DOC_FILES[*]}"
fi

LIC_LINE=""
if [[ "${#LIC_FILES[@]}" -gt 0 ]]; then
  LIC_LINE="%license ${LIC_FILES[*]}"
fi
# -------------------------------------------------------------------------------

cat > "$SPEC" <<EOF
Name:           ${PKGNAME}
Version:        ${VERSION}
Release:        ${RELEASE}%{?dist}
Summary:        Telegram group guard bot (tg-guard)

License:        MIT
URL:            https://github.com/xujiegb/tg-guard
Source0:        %{name}-%{version}.tar.gz

# We ship a prebuilt binary in Source0, so rpmbuild does not need Rust toolchain.
BuildArch:      %{_arch}

# Runtime deps (openssl-sys typically links dynamically to libssl/libcrypto)
Requires:       openssl-libs
Requires:       systemd

%description
tg-guard is a Telegram group guard bot.

It ships as a single binary with a systemd service unit and a config file.

%prep
%autosetup -n %{name}-%{version}

%build
# no build here (binary is already built before rpmbuild)

%install
rm -rf %{buildroot}

# binary
install -D -m 0755 %{name} %{buildroot}%{_bindir}/%{name}

# config (noreplace)
install -D -m 0644 config.yaml %{buildroot}%{_sysconfdir}/tg-guard/config.yaml

# systemd unit
install -D -m 0644 %{name}.service %{buildroot}%{_unitdir}/%{name}.service

# state dir (owned by service user)
install -d -m 0755 %{buildroot}%{_localstatedir}/lib/tg-guard

%pre
# Create tg-guard user/group if not exist
getent group tg-guard >/dev/null || groupadd -r tg-guard
getent passwd tg-guard >/dev/null || useradd -r -g tg-guard -d %{_localstatedir}/lib/tg-guard -s /sbin/nologin -c "tg-guard service user" tg-guard
exit 0

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
${LIC_LINE}
${DOC_LINE}
%{_bindir}/%{name}
%config(noreplace) %{_sysconfdir}/tg-guard/config.yaml
%{_unitdir}/%{name}.service
%dir %{_localstatedir}/lib/tg-guard

%changelog
* $(date "+%a %b %d %Y") tg-guard packager <packager@localhost> - %{version}-%{release}
- Automated build
EOF

echo "[*] Running rpmbuild..."
rpmbuild -ba "$SPEC"

echo
echo "[OK] RPM build finished."
echo "[*] RPMS output directory:"
find "${RPMTOP}/RPMS" -type f -name "${PKGNAME}-${VERSION}-${RELEASE}*.rpm" -print || true
echo
echo "[*] Install test (on clean system):"
echo "    sudo dnf install -y ${RPMTOP}/RPMS/*/${PKGNAME}-${VERSION}-${RELEASE}*.rpm"
echo "    sudo sed -i 's/REPLACE_ME/<YOUR_BOT_TOKEN>/' /etc/tg-guard/config.yaml"
echo "    sudo systemctl daemon-reload"
echo "    sudo systemctl enable --now tg-guard"
echo "    sudo systemctl status tg-guard --no-pager"
EOF
