#include "pin.H"
#include <fstream>
#include <iostream>
#include <map>
#include <vector>
#include <algorithm>
#include <cstdint>

/*
 * rsa_pin.cpp — RSA Key Extractor via MUL-count Side Channel
 *
 * APPROACH:
 * =========
 * Count MUL/IMUL instructions per loop iteration of square-and-multiply.
 *
 * For each bit of the key d:
 *   square only        → fewer MULs  → bit = 0
 *   square + multiply  → more MULs   → bit = 1
 *
 * The loop is identified by finding the backward branch that fires ~64 times.
 * Each iteration's MUL count is compared to a threshold to decode the bit.
 *
 * STRUCTURE OF muls[] ARRAY:
 * ===========================
 *   muls[0]          = MULs before first branch fire = init noise → SKIP
 *   muls[1..last]    = one entry per loop iteration  → DECODE ALL
 *
 * Note: muls[last] (after final branch fire) may look like cleanup but
 * actually contains the LSB multiply — so we include it in decoding.
 * The uint64_t conversion naturally strips leading zeros.
 */

static ADDRINT g_mainLow = 0, g_mainHigh = ~(ADDRINT)0;
static std::vector<std::pair<ADDRINT,int>> g_events; // (addr, 0=MUL 1=branch)

static VOID RecordMul()             { g_events.push_back({0, 0}); }
static VOID RecordBranch(ADDRINT a) { g_events.push_back({a, 1}); }

VOID ImageLoad(IMG img, VOID *) {
    if (IMG_IsMainExecutable(img)) {
        g_mainLow  = IMG_LowAddress(img);
        g_mainHigh = IMG_HighAddress(img);
        std::cerr << "[rsa_pin] Binary: 0x" << std::hex << g_mainLow
                  << "-0x" << g_mainHigh << std::dec << "\n";
    }
}

VOID InstrumentIns(INS ins, VOID *) {
    OPCODE op = INS_Opcode(ins);

    // Record every MUL/IMUL instruction
    if (op == XED_ICLASS_MUL || op == XED_ICLASS_IMUL)
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMul, IARG_END);

    // Record backward branches inside main binary (loop detection)
    if (INS_IsDirectBranch(ins) && INS_HasFallThrough(ins)) {
        ADDRINT addr = INS_Address(ins);
        ADDRINT tgt  = INS_DirectControlFlowTargetAddress(ins);
        if (addr >= g_mainLow && addr < g_mainHigh && tgt < addr)
            INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)RecordBranch,
                           IARG_INST_PTR, IARG_END);
    }
}

// Get MUL counts per iteration for a given loop branch address
static std::vector<int> getMulsPerIter(ADDRINT baddr) {
    std::vector<int> muls;
    int cur = 0;
    for (auto &e : g_events) {
        if (e.second == 0) {
            cur++;
        } else if (e.second == 1 && e.first == baddr) {
            muls.push_back(cur);
            cur = 0;
        }
    }
    muls.push_back(cur);  // last segment after final branch
    return muls;
}

VOID Fini(INT32, VOID *) {
    std::ofstream dbg("debug.txt");

    // ── Step 1: find loop branch (fires closest to 64) ───────────────
    std::map<ADDRINT,int> branchFreq;
    for (auto &e : g_events)
        if (e.second == 1) branchFreq[e.first]++;

    ADDRINT bestBranch = 0;
    int bestDist = 9999;
    for (auto &p : branchFreq) {
        int dist = std::abs(p.second - 64);
        if (dist < bestDist) { bestDist = dist; bestBranch = p.first; }
    }

    int loopFires = branchFreq[bestBranch];
    dbg << "=== LOOP DETECTION ===\n"
        << "Branch: 0x" << std::hex << bestBranch
        << std::dec << "  fires=" << loopFires << "\n\n";
    std::cerr << "[rsa_pin] Loop branch: 0x" << std::hex << bestBranch
              << std::dec << " fires=" << loopFires << "\n";

    // ── Step 2: get MUL counts per iteration ─────────────────────────
    std::vector<int> muls = getMulsPerIter(bestBranch);

    dbg << "=== MUL COUNTS PER ITERATION ===\n";
    std::cerr << "[rsa_pin] Raw MULs/iter (" << muls.size() << "): ";
    for (int m : muls) { dbg << m << " "; std::cerr << m << " "; }
    dbg << "\n\n";
    std::cerr << "\n";

    // ── Step 3: find bit0 and bit1 MUL counts ────────────────────────
    // Use muls[1..last] for frequency (skip muls[0] = init noise)
    std::map<int,int> valFreq;
    for (int i = 1; i < (int)muls.size(); i++)
        valFreq[muls[i]]++;

    dbg << "=== MUL COUNT FREQUENCIES (excluding init) ===\n";
    std::cerr << "[rsa_pin] MUL count frequencies:\n";
    std::vector<std::pair<int,int>> flist;  // (frequency, value)
    for (auto &p : valFreq) {
        flist.push_back({p.second, p.first});
        dbg << "  count=" << p.first << "  freq=" << p.second << "\n";
        std::cerr << "  count=" << p.first << " freq=" << p.second << "\n";
    }
    std::sort(flist.rbegin(), flist.rend());  // sort by frequency desc

    if (flist.size() < 2) {
        dbg << "ERROR: could not find two distinct MUL counts\n";
        std::ofstream out("key.txt"); out << "0\n";
        return;
    }

    // Two most frequent values = bit0_val and bit1_val
    int bit0_val = flist[0].second;
    int bit1_val = flist[1].second;
    if (bit0_val > bit1_val) std::swap(bit0_val, bit1_val);

    double threshold = (bit0_val + bit1_val) / 2.0;

    dbg << "\nbit0_count=" << bit0_val
        << "  bit1_count=" << bit1_val
        << "  threshold=" << threshold << "\n\n";
    std::cerr << "[rsa_pin] bit0_count=" << bit0_val
              << " bit1_count=" << bit1_val
              << " threshold=" << threshold << "\n";

    // ── Step 4: decode bits ───────────────────────────────────────────
    // Skip muls[0] (init noise before loop starts)
    // Decode muls[1] to muls[last] — includes all loop iterations + LSB
    // uint64_t conversion strips leading zeros automatically

    std::vector<int> bits;
    for (int i = 1; i < (int)muls.size(); i++)
        bits.push_back(muls[i] > threshold ? 1 : 0);

    dbg << "=== BIT DECODING ===\n"
        << "bits (" << bits.size() << "): ";
    for (int b : bits) dbg << b;
    dbg << "\n\n";
    std::cerr << "[rsa_pin] bits (" << bits.size() << "): ";
    for (int b : bits) std::cerr << b;
    std::cerr << "\n";

    // ── Step 5: convert to decimal ───────────────────────────────────
    uint64_t key = 0;
    for (int b : bits) key = (key << 1) | (uint64_t)b;

    dbg << "=== RESULT ===\n"
        << "Key (decimal): " << std::dec << key << "\n"
        << "Key (hex):     0x" << std::hex << key << "\n";
    dbg.close();

    std::ofstream out("key.txt");
    out << std::dec << key << "\n";

    std::cerr << "[rsa_pin] Key=" << std::dec << key << "\n"
              << "[rsa_pin] key.txt written\n";
}

int main(int argc, char *argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return 1;
    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    INS_AddInstrumentFunction(InstrumentIns, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);
    PIN_StartProgram();
    return 0;
}
