// Find anything that contains "Map" in its name and print address + form.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class SearchSymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Show image base for sanity
        println("imageBase = 0x" + Long.toHexString(currentProgram.getImageBase().getOffset()));
        println("min addr  = " + currentProgram.getMinAddress());
        println("max addr  = " + currentProgram.getMaxAddress());
        println("function count = " + currentProgram.getFunctionManager().getFunctionCount());
        println("symbol count   = " + currentProgram.getSymbolTable().getNumSymbols());

        // Total symbols and a sample of named ones
        SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
        int n = 0;
        int hits = 0;
        while (it.hasNext() && hits < 25) {
            Symbol s = it.next();
            n++;
            String name = s.getName(true);
            if (name.contains("postUpdate") || name.contains("updateEntities")) {
                println("  [" + s.getAddress() + "] " + name + " (type=" + s.getSymbolType() + ")");
                hits++;
            }
        }
        println("scanned " + n + " symbols, hits=" + hits);
    }
}
