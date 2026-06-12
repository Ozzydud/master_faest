#!/usr/bin/env bash
set -euo pipefail

# Cache-oriented perf study for the FAEST tree traversal experiments.
#
# Default usage from the repository root:
#   ./tools/run_traversal_cache_perf.sh
#
# Useful overrides:
#   OUT_DIR=../server_results/traversal_cache_perf_01 ./tools/run_traversal_cache_perf.sh
#   SCHEMES="faest_192_s faest_256_s" PROFILE_ITERS=200 ./tools/run_traversal_cache_perf.sh
#   RUN_CATCH2=0 ./tools/run_traversal_cache_perf.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

timestamp="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="${OUT_DIR:-../server_results/traversal_cache_perf_${timestamp}}"
CORE="${CORE:-0}"
REPEAT="${REPEAT:-3}"
PROFILE_ITERS="${PROFILE_ITERS:-100}"
SAMPLES="${SAMPLES:-20}"
WARMUP="${WARMUP:-100ms}"
RUN_TESTS="${RUN_TESTS:-0}"
RUN_PROFILE="${RUN_PROFILE:-1}"
RUN_CATCH2="${RUN_CATCH2:-1}"
BENCH_FILTER="${BENCH_FILTER:-*bench vole_commit*}"
SCHEMES="${SCHEMES:-faest_128_s faest_192_s faest_256_s faest_em_128_s faest_em_192_s faest_em_256_s}"
OPERATIONS="${OPERATIONS:-vector_commit}"

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

cat > "$OUT_DIR/README.txt" <<EOF
FAEST traversal cache perf experiment
Generated: ${timestamp}
Repository: ${ROOT_DIR}
Core: ${CORE}
perf repeats: ${REPEAT}
profile iterations: ${PROFILE_ITERS}
Catch2 samples: ${SAMPLES}
Catch2 warmup: ${WARMUP}
Catch2 filter: ${BENCH_FILTER}
Schemes: ${SCHEMES}
Operations: ${OPERATIONS}
Events: ${PERF_EVENTS}

Traversal modes:
  original -> FAEST_TREE_TRAVERSAL=0
  dfs    -> FAEST_TREE_TRAVERSAL=1
  bfs    -> FAEST_TREE_TRAVERSAL=2
  hybrid -> FAEST_TREE_TRAVERSAL=3
  avx512 -> FAEST_TREE_TRAVERSAL=4

The profile_vole_commit runs are the cleaner cache measurements because they
avoid most Catch2 benchmark-loop overhead. The Catch2 runs are included for
continuity with the earlier traversal timing benchmarks.
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
  local name="$1"
  local mode="$2"
  local build_dir="build_tree_cache_${name}"
  local setup_log="$OUT_DIR/${name}_meson_setup.log"
  local compile_log="$OUT_DIR/${name}_meson_compile.log"
  local test_log="$OUT_DIR/${name}_tests.log"

  local cpp_args="-march=native -mtune=native -Wno-psabi -DFAEST_TREE_TRAVERSAL=${mode}"
  local c_args="-march=native -mtune=native"

  if [[ -d "$build_dir" ]]; then
    run_cmd "$setup_log" meson setup "$build_dir" --wipe --buildtype=release -Db_lto=true -Doptimization=3 -Dcpp_args="$cpp_args" -Dc_args="$c_args"
  else
    run_cmd "$setup_log" meson setup "$build_dir" --buildtype=release -Db_lto=true -Doptimization=3 -Dcpp_args="$cpp_args" -Dc_args="$c_args"
  fi

  run_cmd "$compile_log" meson compile -C "$build_dir"

  if [[ "$RUN_TESTS" == "1" ]]; then
    run_cmd "$test_log" "./${build_dir}/test/tests"
  fi

  echo "$build_dir"
}

run_profile_measurements() {
  local name="$1"
  local build_dir="$2"
  local profile_bin="./${build_dir}/test/profile_vole_commit"

  for scheme in $SCHEMES; do
    for op in $OPERATIONS; do
      local prefix="${name}_profile_${scheme}_${op}"
      run_perf \
        "$OUT_DIR/${prefix}_perf.csv" \
        "$OUT_DIR/${prefix}_stdout.txt" \
        "$profile_bin" "$scheme" "$op" "$PROFILE_ITERS"
    done
  done
}

run_catch2_measurement() {
  local name="$1"
  local build_dir="$2"
  local bench_bin="./${build_dir}/test/bench"

  "$bench_bin" --list-tests "$BENCH_FILTER" >"$OUT_DIR/${name}_catch2_matching_tests.txt" 2>&1 || true

  run_perf \
    "$OUT_DIR/${name}_catch2_vole_commit_perf.csv" \
    "$OUT_DIR/${name}_catch2_vole_commit_stdout.txt" \
    "$bench_bin" "$BENCH_FILTER" \
      --benchmark-samples "$SAMPLES" \
      --benchmark-warmup-time "$WARMUP"
}

declare -a MODES=(
  "original:0"
  "dfs:1"
  "bfs:2"
  "hybrid:3"
  "avx512:4"
)

for entry in "${MODES[@]}"; do
  name="${entry%%:*}"
  mode="${entry##*:}"
  echo "=== Building traversal mode ${name} (${mode}) ==="
  build_dir="$(build_mode "$name" "$mode")"

  if [[ "$RUN_PROFILE" == "1" ]]; then
    echo "=== perf profile_vole_commit for ${name} ==="
    run_profile_measurements "$name" "$build_dir"
  fi

  if [[ "$RUN_CATCH2" == "1" ]]; then
    echo "=== perf Catch2 vole_commit benchmark for ${name} ==="
    run_catch2_measurement "$name" "$build_dir"
  fi
done

echo
echo "Traversal cache perf data written to:"
echo "  $OUT_DIR"
