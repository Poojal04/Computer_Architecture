using namespace std;
#include <iostream>
#include <fstream>
#include <iomanip>
#include "pin.H"
#include <unordered_set>
#include <unordered_map>
#include <chrono>

ofstream OutFile;

static UINT64 dynInsCount       = 0;
static bool   inAnalysisWindow  = false;
static UINT64 fastFwdThreshold  = 0;

static UINT64 cntLoads          = 0;
static UINT64 cntStores         = 0;
static UINT64 cntNops           = 0;
static UINT64 cntDirectCalls    = 0;
static UINT64 cntIndirectCalls  = 0;
static UINT64 cntReturns        = 0;
static UINT64 cntUncondBranches = 0;
static UINT64 cntCondBranches   = 0;
static UINT64 cntLogicalOps     = 0;
static UINT64 cntRotateShifts   = 0;
static UINT64 cntFlagOps        = 0;
static UINT64 cntVecIns         = 0;
static UINT64 cntCondMoves      = 0;
static UINT64 cntMmxSseIns      = 0;
static UINT64 cntSysCalls       = 0;
static UINT64 cntFlops          = 0;
static UINT64 cntOthers         = 0;
static UINT64 totalIns          = 0;

static UINT64 totalMemBytesTouched = 0;
static UINT64 maxMemBytesPerIns    = 0;

static UINT64 insSingleChunkCount = 0;
static UINT64 insMultiChunkCount  = 0;
static UINT64 dataSingleChunkCount = 0;
static UINT64 dataMultiChunkCount  = 0;

static UINT64 cntRegReads2   = 0; // D-3
static UINT64 cntRegWrites1  = 0; // D-4
static UINT64 cntMemOps3     = 0; // D-5
static UINT64 cntMemReads1   = 0; // D-6

static INT32     maxImmValue  = INT32_MIN;
static INT32     minImmValue  = INT32_MAX;
static ADDRDELTA maxDispValue = INT32_MIN;
static ADDRDELTA minDispValue = INT32_MAX;

static unordered_set<UINT64> insnFootprintBlocks;
static unordered_set<UINT64> dataFootprintBlocks;

const UINT64 MAX_INS_SIZE     = 16;
const UINT64 MAX_OPERANDS     = 16;
const UINT64 MAX_MEM_OPERANDS = 10;

static UINT64 insSizeDistrib   [MAX_INS_SIZE]     = {0};
static UINT64 insOpCountDistrib[MAX_OPERANDS]     = {0};
static UINT64 memOpDistrib     [MAX_MEM_OPERANDS] = {0}; // D-5
static UINT64 memWriteDistrib  [MAX_MEM_OPERANDS] = {0}; // D-7

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "HW1.out", "specify output file name");
KNOB<UINT64> KnobFastForward(KNOB_MODE_WRITEONCE, "pintool",
    "f", "100000000", "specify fast forward count (in billions)");

ADDRINT ShouldTerminate(void)
{
    return (dynInsCount >= fastFwdThreshold + 1000000000);
}

ADDRINT UpdateAnalysisWindow(void)
{
    return inAnalysisWindow = ((dynInsCount >= fastFwdThreshold) &&
                               (dynInsCount <  fastFwdThreshold + 1000000000));
}

ADDRINT IsInAnalysisWindow(void)
{
    return inAnalysisWindow;
}

VOID IncInsCountByN(UINT32 n) { dynInsCount += n; }

VOID CountLoads(UINT32 n)  { cntLoads   += n; }
VOID CountStores(UINT32 n) { cntStores  += n; }
VOID CountNops()           { cntNops++; }
VOID CountDirectCalls()    { cntDirectCalls++; }
VOID CountIndirectCalls()  { cntIndirectCalls++; }
VOID CountReturns()        { cntReturns++; }
VOID CountUncondBranches() { cntUncondBranches++; }
VOID CountCondBranches()   { cntCondBranches++; }
VOID CountLogicalOps()     { cntLogicalOps++; }
VOID CountRotateShifts()   { cntRotateShifts++; }
VOID CountFlagOps()        { cntFlagOps++; }
VOID CountVecIns()         { cntVecIns++; }
VOID CountCondMoves()      { cntCondMoves++; }
VOID CountMmxSseIns()      { cntMmxSseIns++; }
VOID CountSysCalls()       { cntSysCalls++; }
VOID CountFlops()          { cntFlops++; }
VOID CountOthers()         { cntOthers++; }

VOID RecordInsnFootprint(UINT64 blockIdx)
{
    insnFootprintBlocks.insert(blockIdx);
}

VOID RecordDataFootprint(ADDRINT memAddr, UINT32 accessSize)
{
    for (ADDRINT blockIdx = memAddr / 32;
         blockIdx <= (memAddr + accessSize - 1) / 32;
         blockIdx += 1)
        dataFootprintBlocks.insert(blockIdx);
}

VOID UpdateInsnDistrib(UINT32 insSize, UINT32 opCount)
{
    insSizeDistrib   [insSize]  ++;
    insOpCountDistrib[opCount]  ++;
}

VOID AnalyzeDataChunkAccess(ADDRINT memAddr, UINT32 accessSize)
{
    ADDRINT startBlock = memAddr / 32;
    ADDRINT endBlock   = (memAddr + accessSize - 1) / 32;
    if (startBlock == endBlock) dataSingleChunkCount++;
    else                        dataMultiChunkCount++;
}

VOID AnalyzeInsChunkAccess(BOOL isMulti)
{
    if (isMulti) insMultiChunkCount++;
    else         insSingleChunkCount++;
}

VOID CheckRegOperands(UINT32 nReads, UINT32 nWrites)
{
    if (nReads == 2)  cntRegReads2++;
    if (nWrites == 1) cntRegWrites1++;
}

VOID CheckMemOperands(UINT32 totalOps, UINT32 nReads, UINT32 nWrites)
{
    memOpDistrib[totalOps]++;
    if (totalOps == 3) cntMemOps3++;
    if (nReads == 1)   cntMemReads1++;
    memWriteDistrib[nWrites]++;
}

VOID UpdateImmBounds(ADDRINT localMin, ADDRINT localMax)
{
    if ((INT32)localMin < minImmValue) minImmValue = (INT32)localMin;
    if ((INT32)localMax > maxImmValue) maxImmValue = (INT32)localMax;
}

VOID UpdateMemAnalysis(UINT64 bytesTouched, ADDRINT localDispMin, ADDRINT localDispMax)
{
    totalMemBytesTouched     += bytesTouched;
    if (bytesTouched > maxMemBytesPerIns) maxMemBytesPerIns = bytesTouched;
    if ((ADDRDELTA)localDispMin < minDispValue) minDispValue = (ADDRDELTA)localDispMin;
    if ((ADDRDELTA)localDispMax > maxDispValue) maxDispValue = (ADDRDELTA)localDispMax;
}

static const char *B1 = "+==============================================================+";
static const char *B2 = "+--------------------------------------------------------------+";
static const char *B3 = "+--------------------------+----------------+----------------+";
static const char *B4 = "+--------------------------+----------------+----------------+";

static void PrintRow(const string &label, UINT64 count)
{
    double pct = (totalIns == 0) ? 0.0 : (100.0 * count / totalIns);
    OutFile << "| " << left  << setw(24) << label
            << " | " << right << setw(14) << count
            << " | " << right << setw(12) << fixed << setprecision(6) << pct << "% |\n";
}

static void PrintDistrib(const string &title, const UINT64 *arr, UINT64 sz)
{
    OutFile << "\n  [ " << title << " ]\n";
    OutFile << "  " << string(38, '-') << "\n";
    bool anyNonZero = false;
    for (UINT64 i = 0; i < sz; i++) {
        if (arr[i] == 0) continue;
        anyNonZero = true;
        OutFile << "    " << setw(3) << i << "  ->  " << arr[i] << "\n";
    }
    if (!anyNonZero) OutFile << "    (all zero)\n";
}

void MyExitRoutine()
{
    totalIns = cntLoads + cntStores + cntNops + cntDirectCalls +
               cntIndirectCalls + cntReturns + cntUncondBranches +
               cntCondBranches + cntLogicalOps + cntRotateShifts +
               cntFlagOps + cntVecIns + cntCondMoves + cntMmxSseIns +
               cntSysCalls + cntFlops + cntOthers;

    UINT64 memInsCount = 0;
    for (UINT64 i = 1; i < MAX_MEM_OPERANDS; i++) memInsCount += memOpDistrib[i];
    double avgMemBytes = (memInsCount == 0) ? 0.0
                       : ((double)totalMemBytesTouched / (double)memInsCount);

    UINT64 totalCycles = (cntLoads * 70) + (cntStores * 70) +
                         cntNops + cntDirectCalls + cntIndirectCalls + cntReturns +
                         cntUncondBranches + cntCondBranches + cntLogicalOps +
                         cntRotateShifts + cntFlagOps + cntVecIns + cntCondMoves +
                         cntMmxSseIns + cntSysCalls + cntFlops + cntOthers;

    OutFile << "\n" << B1 << "\n";
    OutFile << "|          CS422 HW1  --  PIN DYNAMIC ANALYSIS REPORT         |\n";
    OutFile << B1 << "\n";
    OutFile << "| Total Dynamic Instructions  : " << left << setw(30) << dynInsCount                        << "|\n";
    OutFile << "| Instructions in Window      : " << left << setw(30) << (dynInsCount - fastFwdThreshold)   << "|\n";
    OutFile << B1 << "\n";

    OutFile << "\n" << B1 << "\n";
    OutFile << "|  PART A : INSTRUCTION MIX                                    |\n";
    OutFile << B3 << "\n";
    OutFile << "| " << left  << setw(24) << "Instruction Type"
            << " | " << right << setw(14) << "Count"
            << " | " << right << setw(14) << "Percentage" << " |\n";
    OutFile << B4 << "\n";

    PrintRow("Loads  (32b chunks)",   cntLoads);
    PrintRow("Stores (32b chunks)",   cntStores);
    PrintRow("NOPs",                  cntNops);
    PrintRow("Direct Calls",          cntDirectCalls);
    PrintRow("Indirect Calls",        cntIndirectCalls);
    PrintRow("Returns",               cntReturns);
    PrintRow("Uncondit. Branches",    cntUncondBranches);
    PrintRow("Condit. Branches",      cntCondBranches);
    PrintRow("Logical Operations",    cntLogicalOps);
    PrintRow("Rotate & Shift",        cntRotateShifts);
    PrintRow("Flag Operations",       cntFlagOps);
    PrintRow("Vector Instructions",   cntVecIns);
    PrintRow("Conditional Moves",     cntCondMoves);
    PrintRow("MMX & SSE",             cntMmxSseIns);
    PrintRow("System Calls",          cntSysCalls);
    PrintRow("Floating-Point",        cntFlops);
    PrintRow("Others",                cntOthers);

    OutFile << B4 << "\n";
    OutFile << "| " << left  << setw(24) << "TOTAL"
            << " | " << right << setw(14) << totalIns
            << " | " << right << setw(12) << "100.000000" << "% |\n";
    OutFile << B1 << "\n";

    OutFile << "\n" << B2 << "\n";
    OutFile << "|  PART B : CPI ESTIMATE                                       |\n";
    OutFile << B2 << "\n";
    OutFile << "|  CPI = (loads*70 + stores*70 + rest*1) / total_instructions  |\n";
    OutFile << "|  CPI = " << left << setw(53) << fixed << setprecision(6)
            << (double)totalCycles / (double)totalIns << "|\n";
    OutFile << B2 << "\n";

    OutFile << "\n" << B2 << "\n";
    OutFile << "|  PART C : MEMORY FOOTPRINT  (32-byte block granularity)      |\n";
    OutFile << B2 << "\n";
    OutFile << "|  Instruction Footprint : "
            << left << setw(6)  << insnFootprintBlocks.size() << " blocks  =  "
            << left << setw(14) << 32 * insnFootprintBlocks.size() << " bytes  |\n";
    OutFile << "|  Data Footprint        : "
            << left << setw(6)  << dataFootprintBlocks.size()  << " blocks  =  "
            << left << setw(14) << 32 * dataFootprintBlocks.size()  << " bytes  |\n";
    OutFile << B2 << "\n";
    
    UINT64 totalInsChunks  = insSingleChunkCount + insMultiChunkCount;
    UINT64 totalDataChunks = dataSingleChunkCount + dataMultiChunkCount;
    
    OutFile << "|  Instructions :                                              |\n";
    OutFile << "|    Single Chunk: " << left << setw(12) << insSingleChunkCount 
            << " (" << fixed << setprecision(4) << (totalInsChunks ? 100.0*insSingleChunkCount/totalInsChunks : 0) << "%)      |\n";
    OutFile << "|    Multi  Chunk: " << left << setw(12) << insMultiChunkCount 
            << " (" << fixed << setprecision(4) << (totalInsChunks ? 100.0*insMultiChunkCount/totalInsChunks : 0) << "%)      |\n";
    OutFile << "|  Data Accesses :                                             |\n";
    OutFile << "|    Single Chunk: " << left << setw(12) << dataSingleChunkCount 
            << " (" << fixed << setprecision(4) << (totalDataChunks ? 100.0*dataSingleChunkCount/totalDataChunks : 0) << "%)      |\n";
    OutFile << "|    Multi  Chunk: " << left << setw(12) << dataMultiChunkCount 
            << " (" << fixed << setprecision(4) << (totalDataChunks ? 100.0*dataMultiChunkCount/totalDataChunks : 0) << "%)      |\n";
    OutFile << B2 << "\n";

    OutFile << "\n" << B2 << "\n";
    OutFile << "|  PART D : ISA PROPERTIES & DISTRIBUTIONS                     |\n";
    OutFile << B2 << "\n";
    PrintDistrib("[D-1] Instruction Size Distribution",         insSizeDistrib,    MAX_INS_SIZE);
    PrintDistrib("[D-2] Total Operand Count   / Instruction",   insOpCountDistrib, MAX_OPERANDS);

    OutFile << "|  [D-3] Instructions with 2 Register Read Operands : " 
            << left << setw(12) << cntRegReads2 << "|\n";
    OutFile << "|  [D-4] Instructions with 1 Register Write Operand : " 
            << left << setw(12) << cntRegWrites1 << "|\n";
    PrintDistrib("[D-5] Instructions with 3 Memory Operands",memOpDistrib, 3);
    OutFile << "    " << setw(3) << 3 << "  ->  " << memOpDistrib[3] << "\n";
    OutFile << "|  [D-6] Instructions with 1 Memory Read Operand    : " 
            << left << setw(12) << cntMemReads1 << "|\n";
    PrintDistrib("[D-7] Instructions with 2 Memory Write Operands", memWriteDistrib, 2);
    OutFile << "    " << setw(3) << 2 << "  ->  " << memWriteDistrib[2] << "\n";
    OutFile << B2 << "\n";

    OutFile << "| [D-8] Max bytes touched by a single instruction : "
            << left << setw(16) << maxMemBytesPerIns  << "|\n";
    OutFile << "|  Avg bytes touched per memory instruction  : "
            << left << setw(16) << fixed << setprecision(6) << avgMemBytes << "|\n";
    OutFile << "| [D-9] Immediate  range  :  [ "
            << setw(12) << minImmValue  << "  ,  " << setw(12) << maxImmValue  << " ] |\n";
    OutFile << "| [D-10] Displacement range:  [ "
            << setw(12) << minDispValue << "  ,  " << setw(12) << maxDispValue << " ] |\n";
    OutFile << B2 << "\n";

    OutFile << "\n" << B1 << "\n";
    OutFile << "|                       END OF REPORT                         |\n";
    OutFile << B1 << "\n\n";

    OutFile.close();
    exit(0);
}

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        BBL_InsertIfCall  (bbl, IPOINT_BEFORE, (AFUNPTR)ShouldTerminate,      IARG_END);
        BBL_InsertThenCall(bbl, IPOINT_BEFORE, (AFUNPTR)MyExitRoutine,        IARG_END);
        BBL_InsertCall    (bbl, IPOINT_BEFORE, (AFUNPTR)UpdateAnalysisWindow,  IARG_END);

        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            UINT32 numMemOps         = INS_MemoryOperandCount(ins);
            UINT32 numReadOps        = 0;
            UINT32 numWriteOps       = 0;
            UINT64 totalBytesTouched = 0;

            ADDRDELTA insDispMax = INT32_MIN, insDispMin = INT32_MAX, dispVal;

            for (UINT32 mIdx = 0; mIdx < numMemOps; mIdx++)
            {
                UINT32 opSize      = INS_MemoryOperandSize(ins, mIdx);
                UINT32 opSizeIn32b = (opSize + 3) / 4; 

                if (INS_MemoryOperandIsRead(ins, mIdx))
                {
                    totalBytesTouched += opSize;
                    numReadOps++;
                    INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountLoads,
                                                IARG_UINT32, opSizeIn32b, IARG_END);
                }
                if (INS_MemoryOperandIsWritten(ins, mIdx))
                {
                    totalBytesTouched += opSize;
                    numWriteOps++;
                    INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountStores,
                                                IARG_UINT32, opSizeIn32b, IARG_END);
                }

                dispVal = INS_OperandMemoryDisplacement(ins, mIdx);
                if (dispVal > insDispMax) insDispMax = dispVal;
                if (dispVal < insDispMin) insDispMin = dispVal;

                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordDataFootprint,
                                            IARG_MEMORYOP_EA, mIdx,
                                            IARG_UINT32, opSize, IARG_END);
                                            
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)AnalyzeDataChunkAccess,
                                            IARG_MEMORYOP_EA, mIdx,
                                            IARG_UINT32, opSize, IARG_END);
            }

            UINT32 numOperands  = INS_OperandCount(ins);
            INT32  insImmMax    = INT32_MIN, insImmMin = INT32_MAX, immVal;
            bool   hasImmediate = false;

            for (UINT32 opIdx = 0; opIdx < numOperands; opIdx++)
            {
                if (INS_OperandIsImmediate(ins, opIdx))
                {
                    hasImmediate = true;
                    immVal = (INT32)INS_OperandImmediate(ins, opIdx);
                    if (immVal < insImmMin) insImmMin = immVal;
                    if (immVal > insImmMax) insImmMax = immVal;
                }
            }

            UINT32 insSize = INS_Size(ins);
            UINT64 insAddr = INS_Address(ins);
            BOOL isInsMulti = ((insAddr / 32) != ((insAddr + insSize - 1) / 32));
            
            INS_InsertIfCall  (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)AnalyzeInsChunkAccess,
                               IARG_BOOL, isInsMulti, IARG_END);

            for (UINT64 blk = insAddr / 32; blk <= (insAddr + insSize - 1) / 32; blk++)
            {
                INS_InsertIfCall  (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInsnFootprint,
                                   IARG_UINT64, blk, IARG_END);
            }

            INS_InsertIfCall  (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)UpdateInsnDistrib,
                               IARG_UINT32, insSize,
                               IARG_UINT32, INS_OperandCount(ins),
                               IARG_END);

            INS_InsertIfCall  (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckRegOperands,
                               IARG_UINT32, INS_MaxNumRRegs(ins), 
                               IARG_UINT32, INS_MaxNumWRegs(ins), 
                               IARG_END);

            if (hasImmediate)
            {
                INS_InsertIfCall  (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)UpdateImmBounds,
                                   IARG_ADDRINT, (ADDRINT)insImmMin,
                                   IARG_ADDRINT, (ADDRINT)insImmMax,
                                   IARG_END);
            }

            INS_InsertIfCall            (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
            INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckMemOperands,
                                         IARG_UINT32, numReadOps + numWriteOps, 
                                         IARG_UINT32, numReadOps,               
                                         IARG_UINT32, numWriteOps,              
                                         IARG_END);

            if (numMemOps >= 1)
            {
                INS_InsertIfCall            (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)UpdateMemAnalysis,
                                             IARG_UINT64,   totalBytesTouched,
                                             IARG_ADDRINT, (ADDRINT)insDispMin,
                                             IARG_ADDRINT, (ADDRINT)insDispMax,
                                             IARG_END);
            }

            UINT32 cat = INS_Category(ins);
            if (cat == XED_CATEGORY_NOP) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountNops, IARG_END);
            }
            else if (cat == XED_CATEGORY_CALL) {
                if (INS_IsDirectCall(ins)) {
                    INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountDirectCalls, IARG_END);
                } else {
                    INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountIndirectCalls, IARG_END);
                }
            }
            else if (cat == XED_CATEGORY_RET) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountReturns, IARG_END);
            }
            else if (cat == XED_CATEGORY_UNCOND_BR) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountUncondBranches, IARG_END);
            }
            else if (cat == XED_CATEGORY_COND_BR) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountCondBranches, IARG_END);
            }
            else if (cat == XED_CATEGORY_LOGICAL) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountLogicalOps, IARG_END);
            }
            else if (cat == XED_CATEGORY_ROTATE || cat == XED_CATEGORY_SHIFT) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountRotateShifts, IARG_END);
            }
            else if (cat == XED_CATEGORY_FLAGOP) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountFlagOps, IARG_END);
            }
            else if (cat == XED_CATEGORY_AVX    || cat == XED_CATEGORY_AVX2 ||
                     cat == XED_CATEGORY_AVX2GATHER || cat == XED_CATEGORY_AVX512) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountVecIns, IARG_END);
            }
            else if (cat == XED_CATEGORY_CMOV) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountCondMoves, IARG_END);
            }
            else if (cat == XED_CATEGORY_MMX || cat == XED_CATEGORY_SSE) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountMmxSseIns, IARG_END);
            }
            else if (cat == XED_CATEGORY_SYSCALL) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountSysCalls, IARG_END);
            }
            else if (cat == XED_CATEGORY_X87_ALU) {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountFlops, IARG_END);
            }
            else {
                INS_InsertIfCall          (ins, IPOINT_BEFORE, (AFUNPTR)IsInAnalysisWindow, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CountOthers, IARG_END);
            }
        }
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)IncInsCountByN,
                       IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    OutFile.setf(ios::showbase);
    OutFile << "Count " << dynInsCount << endl;
    OutFile.close();
}

INT32 Usage()
{
    cerr << "This tool counts and analyses dynamic instructions executed." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());
    fastFwdThreshold = KnobFastForward.Value() * 1000000000ULL;

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}
