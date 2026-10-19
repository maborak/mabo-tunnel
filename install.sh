#!/usr/bin/env bash
# Install release binaries for Linux/macOS. Downloads are checksum-verified
# before any installed binary is replaced.
set -euo pipefail

repo="maborak/mabo-tunnel"
install_dir="${DESTDIR:-${HOME:?HOME must be set}/.local/bin}"
requested_version="${VERSION:-}"
component="all"
binary_path=""
modify_path=true

usage() {
  cat <<'EOF'
mabo-tunnel installer

Usage: install.sh [options]

By default installs mabo-tunnel-client, mabo-tunnel-server, and
mabo-tunnel-token into ~/.local/bin.

Options:
  -h, --help              Show this help
  -v, --version VERSION   Install a specific release (with or without v prefix)
  -c, --component NAME    Install client, server, token, or all (default: all)
  -d, --dir PATH          Install directory (also: DESTDIR=PATH)
  -b, --binary PATH       Install a local binary; requires --component NAME
      --no-modify-path    Do not edit shell configuration files

Examples:
  curl -fsSL https://raw.githubusercontent.com/maborak/mabo-tunnel/main/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/maborak/mabo-tunnel/main/install.sh | bash -s -- --component client
  curl -fsSL https://raw.githubusercontent.com/maborak/mabo-tunnel/main/install.sh | bash -s -- --version v1.2.3
  DESTDIR="$HOME/bin" ./install.sh --component server
EOF
}

die() {
  printf 'mabo-tunnel installer: error: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -v|--version)
      (($# >= 2)) || die "$1 requires a value"
      requested_version="$2"; shift 2 ;;
    -c|--component)
      (($# >= 2)) || die "$1 requires a value"
      component="$2"; shift 2 ;;
    -d|--dir)
      (($# >= 2)) || die "$1 requires a value"
      install_dir="$2"; shift 2 ;;
    -b|--binary)
      (($# >= 2)) || die "$1 requires a value"
      binary_path="$2"; shift 2 ;;
    --no-modify-path) modify_path=false; shift ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

case "$component" in
  client|server|token|all) ;;
  *) die "component must be client, server, token, or all" ;;
esac
[[ -n "$binary_path" && "$component" == all ]] && die "--binary requires --component client, server, or token"

# Resolve a relative or leading-tilde destination without eval.
case "$install_dir" in
  '~/'*) install_dir="$HOME/${install_dir#~/}" ;;
esac
[[ "$install_dir" = /* ]] || install_dir="$PWD/$install_dir"

if [[ -n "$binary_path" ]]; then
  [[ -f "$binary_path" && -r "$binary_path" ]] || die "binary is not a readable file: $binary_path"
  [[ "$(uname -s)" == Linux || "$(uname -s)" == Darwin ]] || die "local binary installation is supported on Linux/macOS only"
  selected="$component"
else
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) os=darwin; arch=arm64 ;;
    Darwin-x86_64|Darwin-i386)
      os=darwin; arch=amd64
      # A shell running under Rosetta should install the native Apple Silicon build.
      if [[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" == 1 ]]; then arch=arm64; fi ;;
    Linux-aarch64|Linux-arm64) os=linux; arch=arm64 ;;
    Linux-x86_64|Linux-i386) os=linux; arch=amd64 ;;
    *) die "no release binaries for $(uname -s) $(uname -m); use Go or build from source" ;;
  esac
  selected="$component"
fi

case "$selected" in
  all) binaries=(client server token) ;;
  *) binaries=("$selected") ;;
esac

# Keep temporary downloads private. Create the install directory only after
# argument/platform validation; honor explicit DESTDIR instead of silently
# falling back to some other location.
umask 077
tmp="$(mktemp -d "${TMPDIR:-/tmp}/mabo-tunnel-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$install_dir" || die "cannot create install directory: $install_dir"
[[ -w "$install_dir" ]] || die "$install_dir is not writable; choose --dir or DESTDIR"

if [[ -n "$binary_path" ]]; then
  cp "$binary_path" "$tmp/$component"
  chmod 0755 "$tmp/$component"
else
  if [[ -n "$requested_version" ]]; then
    tag="${requested_version#v}"
    release_ref="v${tag}"
    [[ "$requested_version" == v* ]] && release_ref="$requested_version"
  else
    release_ref="$(curl -fsSLI "https://github.com/${repo}/releases/latest" \
      | sed -n 's/^[Ll]ocation: .*\/tag\///p' | tr -d '\r' | tail -n1)"
    tag="${release_ref#v}"
  fi
  [[ -n "$tag" && -n "$release_ref" ]] || die "could not resolve release version"
  base="https://github.com/${repo}/releases/download/${release_ref}"

  say="mabo-tunnel installer:"
  printf '%s downloading release %s for %s/%s\n' "$say" "$tag" "$os" "$arch"
  curl -fsSL "$base/SHA256SUMS.txt" -o "$tmp/SHA256SUMS.txt" || die "release $tag has no SHA256SUMS.txt"
  for name in "${binaries[@]}"; do
    asset="mabo-tunnel-${name}-${os}-${arch}"
    curl -fsSL "$base/$asset" -o "$tmp/$asset" || die "release $tag does not provide $asset"
    if command -v shasum >/dev/null 2>&1; then
      actual="$(cd "$tmp" && shasum -a 256 "$asset" | awk '{print $1}')"
    elif command -v sha256sum >/dev/null 2>&1; then
      actual="$(cd "$tmp" && sha256sum "$asset" | awk '{print $1}')"
    else
      die "shasum or sha256sum is required to verify downloads"
    fi
    expected="$(awk -v a="$asset" '$2 == a {print $1}' "$tmp/SHA256SUMS.txt" | head -n1)"
    [[ -n "$expected" && "$actual" == "$expected" ]] || die "checksum verification failed for $asset"
    mv "$tmp/$asset" "$tmp/$name"
    chmod 0755 "$tmp/$name"
  done
fi

# Stage all files beside their destinations, then rename into place. Every
# remote artifact has already passed checksum verification before this begins.
for name in "${binaries[@]}"; do
  case "$name" in
    client) target=mabo-tunnel-client ;;
    server) target=mabo-tunnel-server ;;
    token) target=mabo-tunnel-token ;;
  esac
  staged="$(mktemp "$install_dir/.${target}.tmp.XXXXXX")" || die "cannot stage $target in $install_dir"
  install -m 0755 "$tmp/$name" "$staged"
  mv -f "$staged" "$install_dir/$target"
  printf 'mabo-tunnel installer: installed %s\n' "$install_dir/$target"
done

if [[ "$modify_path" == true && ":$PATH:" != *":$install_dir:"* ]]; then
  shell_name="$(basename "${SHELL:-sh}")"
  config=""
  case "$shell_name" in
    zsh) config="${ZDOTDIR:-$HOME}/.zshrc" ;;
    bash) config="$HOME/.bashrc"; [[ -e "$config" ]] || config="$HOME/.bash_profile" ;;
    fish) config="$HOME/.config/fish/config.fish" ;;
    *) ;;
  esac

  if [[ -n "$config" ]]; then
    # Only interpolate simple path characters into startup files. For unusual
    # paths, avoid generating shell code from user input and explain the manual
    # step instead.
    if [[ "$install_dir" =~ ^[A-Za-z0-9_./-]+$ ]]; then
      mkdir -p "$(dirname "$config")"
      touch "$config" || die "cannot update shell configuration $config; add $install_dir to PATH manually"
      if [[ "$shell_name" == fish ]]; then
        path_line="fish_add_path $install_dir"
      else
        path_line="export PATH=\"\$PATH:$install_dir\""
      fi
      if ! grep -Fqx "$path_line" "$config"; then
        printf '\n# mabo-tunnel\n%s\n' "$path_line" >> "$config" || die "cannot update $config; add $install_dir to PATH manually"
        printf 'mabo-tunnel installer: added %s to PATH in %s (open a new shell)\n' "$install_dir" "$config"
      fi
    else
      printf 'mabo-tunnel installer: add %s to PATH manually (path not shell-safe for automatic config editing)\n' "$install_dir"
    fi
  else
    printf 'mabo-tunnel installer: add %s to PATH manually\n' "$install_dir"
  fi
fi

[[ -n "${GITHUB_PATH:-}" && -w "${GITHUB_PATH:-/dev/null}" ]] && printf '%s\n' "$install_dir" >> "$GITHUB_PATH"

if [[ -n "$binary_path" ]]; then
  printf 'mabo-tunnel installer: installed local %s binary\n' "$component"
else
  printf 'mabo-tunnel installer: installation complete (%s)\n' "$tag"
fi
