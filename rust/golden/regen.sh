#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/rust/auks-cred/tests/vectors"
BIN="$ROOT/rust/golden/gen_vectors"

mkdir -p "$OUT"
cc ${CFLAGS:-} \
	-I"$ROOT/src/api" \
	$(pkg-config --cflags libtirpc krb5) \
	"$ROOT/rust/golden/gen_vectors.c" \
	-Wl,--start-group \
	"$ROOT/src/api/auks/.libs/libauksapi.a" \
	"$ROOT/src/api/confparse/.libs/libconfig_parsing.a" \
	"$ROOT/src/api/xternal/.libs/libxternal.a" \
	-Wl,--end-group \
	$(pkg-config --libs libtirpc krb5) \
	-pthread \
	-o "$BIN"
"$BIN" "$OUT"
rm -f "$BIN"

if git -C "$ROOT" diff --exit-code -- "$OUT"; then
	printf '%s\n' "golden vectors are unchanged"
fi
