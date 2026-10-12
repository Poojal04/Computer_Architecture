#!/bin/bash
# ─────────────────────────────────────────────────────
# Run from: ~/CS422/pin-dir/source/tools/HW1/
# ─────────────────────────────────────────────────────

# Absolute paths — safe even after cd into benchmark dirs
PIN="$HOME/Desktop/CS422/pin-dir/pin"
TOOL="$HOME/Desktop/CS422/pin-dir/source/tools/HW1/obj-ia32/HW1.so"
SPEC_ROOT="$HOME/Desktop/CS422/spec_2006"

# ─── Generic helper: cd into bench dir and run pin ───
run_bench() {
    local BENCH_DIR=$1
    local FF=$2
    local CMD=$3
    echo "Starting $BENCH_DIR ..."
    (
        cd "$SPEC_ROOT/$BENCH_DIR" || { echo "ERROR: cannot cd to $BENCH_DIR"; exit 1; }
        $PIN -t $TOOL -o pin_final.out -f $FF -- $CMD
        echo "Done: $BENCH_DIR"
    ) &
}

# ─────────────────────────────────────────────────────
# MANDATORY 8 — run in parallel, wait for all
# ─────────────────────────────────────────────────────

run_bench "400.perlbench" 207 \
    "./perlbench_base.i386 -I./lib diffmail.pl 4 800 10 17 19 300"

run_bench "401.bzip2" 301 \
    "./bzip2_base.i386 input.source 280"

run_bench "403.gcc" 107 \
    "./gcc_base.i386 cp-decl.i -o cp-decl.s"

run_bench "429.mcf" 377 \
    "./mcf_base.i386 inp.in"

run_bench "450.soplex" 364 \
    "./soplex_base.i386 -m3500 ref.mps"

run_bench "456.hmmer" 264 \
    "./hmmer_base.i386 nph3.hmm swiss41"

run_bench "471.omnetpp" 43 \
    "./omnetpp_base.i386 omnetpp.ini"

run_bench "483.xalancbmk" 1331 \
    "./xalancbmk_base.i386 -v t5.xml xalanc.xsl"

wait
echo "============================================"
echo "First 8 mandatory benchmarks completed."
echo "============================================"

# ─────────────────────────────────────────────────────
# OPTIONAL 5 — run in parallel, wait for all
# ─────────────────────────────────────────────────────

run_bench "436.cactusADM" 584 \
    "./cactusADM_base.i386 benchADM.par"

# leslie3d uses stdin redirect — must be special-cased
echo "Starting 437.leslie3d ..."
(
    cd "$SPEC_ROOT/437.leslie3d" || { echo "ERROR: cannot cd to 437.leslie3d"; exit 1; }
    $PIN -t $TOOL -o pin.out -f 2346 -- \
        ./leslie3d_base.i386 < leslie3d.in
    echo "Done: 437.leslie3d"
) &

run_bench "462.libquantum" 3605 \
    "./libquantum_base.i386 1397 8"

run_bench "470.lbm" 830 \
    "./lbm_base.i386 3000 reference.dat 0 0 100_100_130_ldc.of"

# sphinx3 has a nested directory structure — must be special-cased
echo "Starting 482.sphinx3 ..."
(
    cd "$SPEC_ROOT/482.sphinx3/1/2/482.sphinx3" || { echo "ERROR: cannot cd to 482.sphinx3 nested dir"; exit 1; }
    $PIN -t $TOOL -o pin.out -f 1513 -- \
        ./sphinx3_base.i386 ctlfile . args.an4
    echo "Done: 482.sphinx3"
) &

wait
echo "============================================"
echo "All benchmarks completed."
echo "============================================"
