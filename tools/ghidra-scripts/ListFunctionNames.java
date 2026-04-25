// Diagnostic: print the first 30 function names in every form Ghidra exposes.
// Helps debug why a regex isn't matching.
//
// Usage:
//   analyzeHeadless re/ghidra-project factorio -process factorio \
//     -scriptPath tools/ghidra-scripts \
//     -postScript ListFunctionNames.java -noanalysis -readOnly

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class ListFunctionNames extends GhidraScript {
    @Override
    public void run() throws Exception {
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int n = 0;
        while (it.hasNext() && n < 30) {
            Function fn = it.next();
            String addr = fn.getEntryPoint().toString();
            String getName_false = fn.getName();
            String getName_true = fn.getName(true);
            String symName_false = fn.getSymbol().getName();
            String symName_true = fn.getSymbol().getName(true);
            String parentNs = fn.getParentNamespace().getName(true);
            String sig = fn.getSignature(true).getPrototypeString(true);
            println("[" + n + "] @0x" + addr);
            println("  getName()         = " + getName_false);
            println("  getName(true)     = " + getName_true);
            println("  symbol.getName()  = " + symName_false);
            println("  sym.getName(true) = " + symName_true);
            println("  parentNamespace   = " + parentNs);
            println("  signature         = " + sig);
            n++;
        }
    }
}
