#!/usr/bin/env bash
set -euo pipefail

# Portfolio sweep for per-parameter-set FAEST optimization choices.
#
# The usual final build uses one set of optimization choices for all schemes.
# This script instead sweeps the available compile-time choices so the thesis can
# report an "oracle" result: for each scheme, what is the best traversal/PRG
# combination observed on the benchmark machine?
#
# Default usage from the repository root:
#   ./tools/run_portfolio_sweep.sh
#
# Useful overrides:
#   SCHEMES="faest_192_s faest_256_s" ./tools/run_portfolio_sweep.sh
#   TRAVERSALS="0 2 3 4" VAES_MODES="0 1" ./tools/run_portfolio_sweep.sh
#   KECCAK_MODES="avx2 avx512" ./tools/run_portfolio_sweep.sh
#   SAMPLES=50 WARMUP=100ms RUN_TESTS=1 ./tools/run_portfolio_sweep.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

timestamp="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="${OUT_DIR:-../server_results/portfolio_sweep_${timestamp}}"
BUILD_DIR_PREFIX="${BUILD_DIR_PREFIX:-build_portfolio}"
CORE="${CORE:-0}"
SAMPLES="${SAMPLES:-30}"
WARMUP="${WARMUP:-100ms}"
RUN_TESTS="${RUN_TESTS:-0}"
TRAVERSALS="${TRAVERSALS:-0 1 2 3 4}"
VAES_MODES="${VAES_MODES:-0 1}"
KECCAK_MODES="${KECCAK_MODES:-avx2}"
OPERATIONS="${OPERATIONS:-sign verify}"
SCHEMES="${SCHEMES:-faest_128_s faest_128_f faest_192_s faest_192_f faest_256_s faest_256_f faest_em_128_s faest_em_128_f faest_em_192_s faest_em_192_f faest_em_256_s faest_em_256_f}"

mkdir -p "$OUT_DIR"

cat > "$OUT_DIR/README.txt" <<EOF
FAEST per-scheme portfolio sweep
Generated: ${timestamp}
Repository: ${ROOT_DIR}
Build directory prefix: ${BUILD_DIR_PREFIX}
Core: ${CORE}
Catch2 samples: ${SAMPLES}
Catch2 warmup: ${WARMUP}
Run tests for each build: ${RUN_TESTS}
Traversal modes: ${TRAVERSALS}
VAES modes: ${VAES_MODES}
Keccak modes: ${KECCAK_MODES}
Operations: ${OPERATIONS}
Schemes: ${SCHEMES}

Traversal modes:
  0 original implementation path
  1 depth-first
  2 breadth-first
  3 chunked hybrid
  4 AVX-512 data-movement hybrid

VAES modes:
  0 FAEST_USE_VAES disabled
  1 FAEST_USE_VAES enabled

Keccak modes:
  avx2   default XKCP AVX2 Keccak backend
  avx512 opt-in XKCP AVX-512 Keccak backend

The intended analysis is not to claim that a production library should ship one
binary per scheme. Instead, this sweep provides an upper-bound/oracle comparison:
how much performance is available if each parameter set selects the best measured
combination of traversal and PRG-related compile-time choices?
EOF

printf 'config_id,tree_traversal,vaes,keccak,build_dir,cpp_args,xkcp_avx512_keccak\n' \
  > "$OUT_DIR/configs.csv"

run_cmd() {
  local log_file="$1"
  shift
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n'
    "$@"
  } >"$log_file" 2>&1
}

build_config() {
  local traversal="$1"
  local vaes="$2"
  local keccak="$3"
  local config_id="t${traversal}_v${vaes}_k${keccak}"
  local build_dir="${BUILD_DIR_PREFIX}_${config_id}"
  local cpp_args="-march=native -mtune=native -Wno-psabi -DFAEST_TREE_TRAVERSAL=${traversal} -DFAEST_USE_VAES=${vaes}"
  local c_args="-march=native -mtune=native"
  local xkcp_avx512=false

  case "$keccak" in
    avx2) xkcp_avx512=false ;;
    avx512) xkcp_avx512=true ;;
    *)
      echo "Unsupported Keccak mode: $keccak" >&2
      echo "Use KECCAK_MODES=\"avx2 avx512\" or a subset." >&2
      exit 2
      ;;
  esac

  if [[ -d "$build_dir" ]]; then
    run_cmd "$OUT_DIR/${config_id}_meson_setup.log" \
      meson setup "$build_dir" --wipe --buildtype=release -Db_lto=true -Doptimization=3 \
        -Dcpp_args="$cpp_args" -Dc_args="$c_args" -Dxkcp:avx512_keccak="$xkcp_avx512"
  else
    run_cmd "$OUT_DIR/${config_id}_meson_setup.log" \
      meson setup "$build_dir" --buildtype=release -Db_lto=true -Doptimization=3 \
        -Dcpp_args="$cpp_args" -Dc_args="$c_args" -Dxkcp:avx512_keccak="$xkcp_avx512"
  fi

  run_cmd "$OUT_DIR/${config_id}_meson_compile.log" meson compile -C "$build_dir"

  if [[ "$RUN_TESTS" == "1" ]]; then
    run_cmd "$OUT_DIR/${config_id}_tests.log" "./${build_dir}/test/tests"
  fi

  printf '%s,%s,%s,%s,%s,"%s",%s\n' \
    "$config_id" "$traversal" "$vaes" "$keccak" "$build_dir" "$cpp_args" "$xkcp_avx512" \
    >> "$OUT_DIR/configs.csv"

  echo "$build_dir"
}

run_benchmark() {
  local config_id="$1"
  local build_dir="$2"
  local operation="$3"
  local scheme="$4"
  local bench_bin="./${build_dir}/test/bench"
  local filter="bench ${operation} - v2::${scheme}"
  local log_file="$OUT_DIR/${config_id}_${operation}_${scheme}.txt"

  {
    printf '$ %q --list-tests %q\n' "$bench_bin" "$filter"
    "$bench_bin" --list-tests "$filter" || true
    printf '\n$ %q %q --benchmark-samples %q --benchmark-warmup-time %q\n' \
      "$bench_bin" "$filter" "$SAMPLES" "$WARMUP"
    taskset -c "$CORE" "$bench_bin" "$filter" \
      --benchmark-samples "$SAMPLES" \
      --benchmark-warmup-time "$WARMUP"
  } >"$log_file" 2>&1
}

for traversal in $TRAVERSALS; do
  for vaes in $VAES_MODES; do
    for keccak in $KECCAK_MODES; do
      config_id="t${traversal}_v${vaes}_k${keccak}"
      echo "=== Building ${config_id} ==="
      build_dir="$(build_config "$traversal" "$vaes" "$keccak")"

      for operation in $OPERATIONS; do
        for scheme in $SCHEMES; do
          echo "=== ${config_id} ${operation} ${scheme} ==="
          run_benchmark "$config_id" "$build_dir" "$operation" "$scheme"
        done
      done
    done
  done
done

echo
echo "Portfolio sweep data written to:"
echo "  $OUT_DIR"
