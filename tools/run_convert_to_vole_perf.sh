#!/usr/bin/env bash
set -euo pipefail

# Focused perf study for the ConvertToVOLE/small-VOLE part of FAEST.
#
# Default usage from the repository root:
#   ./tools/run_convert_to_vole_perf.sh
#
# Useful overrides:
#   PROFILE_ITERS=500 ./tools/run_convert_to_vole_perf.sh
#   SCHEMES="faest_128_s faest_256_s" ./tools/run_convert_to_vole_perf.sh
#   OPERATIONS="convert_to_vole_sender convert_to_vole_receiver small_vole_sender_min small_vole_sender_max" ./tools/run_convert_to_vole_perf.sh
#   MODES="base vaes" ./tools/run_convert_to_vole_perf.sh
#   RUN_TESTS=1 ./tools/run_convert_to_vole_perf.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

timestamp="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="${OUT_DIR:-../server_results/convert_to_vole_perf_${timestamp}}"
BUILD_DIR_PREFIX="${BUILD_DIR_PREFIX:-build_convert_to_vole_perf}"
CORE="${CORE:-0}"
REPEAT="${REPEAT:-3}"
PROFILE_ITERS="${PROFILE_ITERS:-300}"
RUN_TESTS="${RUN_TESTS:-0}"
TREE_TRAVERSAL="${TREE_TRAVERSAL:-4}"
SCHEMES="${SCHEMES:-faest_128_s faest_192_s faest_256_s faest_em_128_s faest_em_192_s faest_em_256_s}"
OPERATIONS="${OPERATIONS:-convert_to_vole_sender convert_to_vole_receiver}"
MODES="${MODES:-base vaes}"

mkdir -p "$OUT_DIR"

EVENTS_FULL="${EVENTS:-cycles,instructions,branches,branch-misses,cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses,dTLB-loads,dTLB-load-misses}"
EVENTS_FALLBACK="cycles,instructions,branches,branch-misses,cache-references,cache-misses"

if perf stat -e "$EVENTS_FULL" -- true >/dev/null 2>"$OUT_DIR/perf_event_probe.txt"; then
  PERF_EVENTS="$EVENTS_FULL"
else
  PERF_EVENTS="$EVENTS_FALLBACK"
  {
    echo "Full cache event set was not accepted by perf."
    echo "Falling back to: $PERF_EVENTS"
    echo
    echo "Original perf probe output:"
    cat "$OUT_DIR/perf_event_probe.txt"
  } > "$OUT_DIR/perf_event_fallback.txt"
fi

c_args="-march=native -mtune=native"

cat > "$OUT_DIR/README.txt" <<EOF
FAEST ConvertToVOLE perf experiment
Generated: ${timestamp}
Repository: ${ROOT_DIR}
Build directory prefix: ${BUILD_DIR_PREFIX}
Core: ${CORE}
perf repeats: ${REPEAT}
profile iterations: ${PROFILE_ITERS}
Schemes: ${SCHEMES}
Operations: ${OPERATIONS}
Modes: ${MODES}
Events: ${PERF_EVENTS}
Tree traversal macro: ${TREE_TRAVERSAL}
C args: ${c_args}

Modes:
  base -> FAEST_USE_VAES=0
  vaes -> FAEST_USE_VAES=1

Operations:
  convert_to_vole_sender   full prover-side ConvertToVOLE loop over all tau small-VOLE instances
  convert_to_vole_receiver full verifier-side ConvertToVOLE loop over all tau small-VOLE instances
  small_vole_sender_min    one prover-side small-VOLE call using MIN_K
  small_vole_sender_max    one prover-side small-VOLE call using MAX_K
  small_vole_receiver_min  one verifier-side small-VOLE call using MIN_K
  small_vole_receiver_max  one verifier-side small-VOLE call using MAX_K

The standalone profile binary avoids Catch2 benchmark-loop overhead. Its JSON
stdout includes the relevant parameter shape: tau, MIN_K/MAX_K, VOLE_WIDTH,
PRG_VOLE_BLOCKS, and VOLE_COL_BLOCKS.
EOF

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

run_perf() {
  local stat_file="$1"
  local stdout_file="$2"
  shift 2
  perf stat \
    -r "$REPEAT" \
    -x, \
    -o "$stat_file" \
    -e "$PERF_EVENTS" \
    -- taskset -c "$CORE" "$@" >"$stdout_file" 2>&1
}

build_mode() {
  local mode="$1"
  local vaes_flag
  local build_dir="${BUILD_DIR_PREFIX}_${mode}"

  case "$mode" in
    base) vaes_flag=0 ;;
    vaes) vaes_flag=1 ;;
    *)
      echo "Unsupported mode: $mode" >&2
      echo "Use MODES=\"base vaes\" or a subset." >&2
      exit 2
      ;;
  esac

  local cpp_args="-march=native -mtune=native -Wno-psabi -DFAEST_USE_VAES=${vaes_flag}"
  if [[ -n "$TREE_TRAVERSAL" ]]; then
    cpp_args="${cpp_args} -DFAEST_TREE_TRAVERSAL=${TREE_TRAVERSAL}"
  fi

  echo "$cpp_args" > "$OUT_DIR/${mode}_cpp_args.txt"

  if [[ -d "$build_dir" ]]; then
    run_cmd "$OUT_DIR/${mode}_meson_setup.log" meson setup "$build_dir" --wipe --buildtype=release -Db_lto=true -Doptimization=3 -Dcpp_args="$cpp_args" -Dc_args="$c_args"
  else
    run_cmd "$OUT_DIR/${mode}_meson_setup.log" meson setup "$build_dir" --buildtype=release -Db_lto=true -Doptimization=3 -Dcpp_args="$cpp_args" -Dc_args="$c_args"
  fi

  run_cmd "$OUT_DIR/${mode}_meson_compile.log" meson compile -C "$build_dir"

  if [[ "$RUN_TESTS" == "1" ]]; then
    run_cmd "$OUT_DIR/${mode}_tests.log" "./${build_dir}/test/tests"
  fi

  echo "$build_dir"
}

for mode in $MODES; do
  echo "=== Building ${mode} mode ==="
  build_dir="$(build_mode "$mode")"
  profile_bin="./${build_dir}/test/profile_vole_commit"

  for scheme in $SCHEMES; do
    for op in $OPERATIONS; do
      prefix="${mode}_${scheme}_${op}"
      echo "=== ${mode} ${scheme} ${op} ==="
      run_perf \
        "$OUT_DIR/${prefix}_perf.csv" \
        "$OUT_DIR/${prefix}_stdout.txt" \
        "$profile_bin" "$scheme" "$op" "$PROFILE_ITERS"
    done
  done
done

echo
echo "ConvertToVOLE perf data written to:"
echo "  $OUT_DIR"
