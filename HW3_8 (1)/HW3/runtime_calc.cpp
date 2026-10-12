#include "pin.H"
#include <iostream>
#include <fstream>
#include <iomanip>

using namespace std;

// Global counters
UINT64 insCount = 0; 
UINT64 memOpsCount = 0;

std::ostream *out = &cerr;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "HW3.out", "specify output file name");

INT32 Usage() {
    cerr << "This tool calculates CPI and Total Cycles for Assignment 3." << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

// Analysis functions to increment counters
VOID count_insbb(UINT32 x) { insCount += x; }
VOID count_mem(UINT32 x) { memOpsCount += x; }

// Instrumentation function
VOID Trace(TRACE trace, VOID *v) { 
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) { 
        
        // Count total instructions at the basic block level for performance
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)count_insbb, IARG_UINT32, BBL_NumIns(bbl), IARG_END); 
        
        for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            
            UINT32 memOperands = INS_MemoryOperandCount(ins);
            for (UINT32 memOper = 0; memOper < memOperands; memOper++) {
                
                UINT32 memSize = INS_MemoryOperandSize(ins, memOper);
                UINT32 num = (memSize % 8 == 0) ? memSize / 8 : (memSize / 8) + 1;
                
                // Predicated call ensures we only count executed memory accesses.
                if (INS_MemoryOperandIsRead(ins, memOper) || INS_MemoryOperandIsWritten(ins, memOper)) {
                    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_mem, IARG_UINT32, num, IARG_END);
                }
            }
        }
    }
}

// Exit routine to compute and print final metrics
void MyExitRoutine() {
    // Memory ops take 5 cycles total and other instructions take 1 cycle.
    UINT64 total_cycles = insCount + (memOpsCount * 4);
    double cpi = (insCount == 0) ? 0.0 : ((double)total_cycles / insCount);

    *out << "============================================================" << endl;
    *out << "Assignment 3 Performance Evaluation" << endl;
    *out << "------------------------------------------------------------" << endl;
    *out << left << setw(30) << "Total Instructions:" << insCount << endl;
    *out << left << setw(30) << "Memory Operations Count:" << memOpsCount << endl;
    *out << left << setw(30) << "Total Cycles:" << total_cycles << endl;
    *out << left << setw(30) << "Average CPI:" << fixed << setprecision(6) << cpi << endl;
    *out << "============================================================" << endl;
}

VOID Fini(INT32 code, VOID *v) { 
    MyExitRoutine(); 
}

int main(int argc, char *argv[]) {

    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    string fileName = KnobOutputFile.Value();
    if (!fileName.empty()) {
        out = new std::ofstream(fileName.c_str());
    }

    // Register instrumentation
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register exit function
    PIN_AddFiniFunction(Fini, 0);

    // Start program execution
    PIN_StartProgram();

    return 0;
}