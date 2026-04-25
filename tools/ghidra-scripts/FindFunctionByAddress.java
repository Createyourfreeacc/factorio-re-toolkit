// Diagnostic: look up the function at known engine addresses and dump everything.
//
// Map::postUpdate is at file VMA 0x2569450 in our nm output.
// Show what Ghidra calls that function under all naming forms.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class FindFunctionByAddress extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] addrs = { 0x2569450L, 0x256e430L, 0x255c9d0L, 0x1c49790L, 0x22b3060L };
        for (long a : addrs) {
            Address ga = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);
            Function fn = currentProgram.getFunctionManager().getFunctionAt(ga);
            println("=== address 0x" + Long.toHexString(a) + " ===");
            if (fn == null) {
                println("  no function defined here");
                continue;
            }
            println("  getName()         = " + fn.getName());
            println("  getName(true)     = " + fn.getName(true));
            println("  symbol.getName(t) = " + fn.getSymbol().getName(true));
            println("  parentNamespace   = " + fn.getParentNamespace().getName(true));
            println("  signature         = " + fn.getSignature(true).getPrototypeString(true));
            println("  isExternal()      = " + fn.isExternal());
        }
    }
}
