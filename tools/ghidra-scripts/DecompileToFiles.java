// Ghidra headless script: decompile every function in `re/symbols/defined.txt`
// whose demangled name matches a regex.
//
// Why use defined.txt instead of Ghidra's own function list:
//   Ghidra's DWARF importer drops the C++ namespace from function names
//   (Map::postUpdate becomes just "postUpdate"). nm's demangled output
//   keeps the full signature, which is what we want to filter on.
//
// Usage (headless):
//   analyzeHeadless <project_path> <project_name> -process <prog_name> \
//     -scriptPath <dir> -postScript DecompileToFiles.java \
//        <symbolsFile> <outputRoot> <regex>
//
// Args:
//   symbolsFile : path to nm --demangle --defined-only --format=bsd output
//   outputRoot  : directory to write .c files into (created if missing)
//   regex       : Java regex matched against the demangled signature
//
// Example:
//   analyzeHeadless re/ghidra-project factorio -process factorio \
//     -scriptPath tools/ghidra-scripts \
//     -postScript DecompileToFiles.java \
//        re/symbols/defined.txt re/decompiled/Map '^Map::'
//
// @category Factorio

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DecompileToFiles extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            printerr("usage: DecompileToFiles <symbolsFile> <outputRoot> <regex>");
            return;
        }
        Path symbolsFile = Paths.get(args[0]);
        Path outputRoot = Paths.get(args[1]);
        Pattern pattern = Pattern.compile(args[2]);
        Files.createDirectories(outputRoot);

        long imageBase = currentProgram.getImageBase().getOffset();
        println("imageBase = 0x" + Long.toHexString(imageBase));
        println("filtering " + symbolsFile + " with regex: " + args[2]);

        // nm BSD format: "<addr> <type> <name>"
        Pattern lineRe = Pattern.compile("^([0-9a-f]+)\\s+([A-Za-z])\\s+(.+)$");

        // Collect (address, demangled) for every matching defined function symbol.
        List<long[]> addrs = new ArrayList<>();
        List<String> names = new ArrayList<>();
        int totalLines = 0, kept = 0;
        for (String line : Files.readAllLines(symbolsFile)) {
            totalLines++;
            Matcher m = lineRe.matcher(line);
            if (!m.matches()) continue;
            String t = m.group(2);
            if (!t.equals("T") && !t.equals("t") && !t.equals("W") && !t.equals("w")
                && !t.equals("i") && !t.equals("u")) continue;
            String name = m.group(3);
            if (!pattern.matcher(name).find()) continue;
            long off = Long.parseUnsignedLong(m.group(1), 16);
            addrs.add(new long[]{off});
            names.add(name);
            kept++;
        }
        println("scanned " + totalLines + " symbol lines, kept " + kept + " matches");
        if (kept == 0) {
            println("no matches; check regex");
            return;
        }

        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decomp.setOptions(opts);
        decomp.toggleSyntaxTree(false);
        decomp.toggleCCode(true);
        if (!decomp.openProgram(currentProgram)) {
            printerr("failed to open program for decompilation");
            return;
        }

        int written = 0, failed = 0, missing = 0;
        long t0 = System.currentTimeMillis();
        for (int i = 0; i < addrs.size(); i++) {
            if (monitor.isCancelled()) break;
            long off = addrs.get(i)[0];
            String demangled = names.get(i);
            Address ga = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(off + imageBase);
            Function fn = currentProgram.getFunctionManager().getFunctionAt(ga);
            if (fn == null) {
                // Try to coerce: maybe Ghidra has a function that contains this addr
                fn = currentProgram.getFunctionManager().getFunctionContaining(ga);
                if (fn == null) {
                    missing++;
                    if (missing <= 5) {
                        println("  no function at 0x" + Long.toHexString(off + imageBase)
                                + " (" + demangled + ")");
                    }
                    continue;
                }
            }
            DecompileResults res = decomp.decompileFunction(fn, 90, monitor);
            if (res == null || !res.decompileCompleted()) {
                failed++;
                if (failed <= 5) {
                    println("  decompile failed: " + demangled
                            + (res != null ? " (" + res.getErrorMessage() + ")" : ""));
                }
                continue;
            }
            String code = res.getDecompiledFunction().getC();
            String safe = demangled.replaceAll("[^A-Za-z0-9._:+-]", "_");
            // eCryptfs caps encrypted filenames at 143 bytes. Stay well under.
            // When the demangled name is too long, truncate and append a hash
            // so different overloads still get distinct filenames.
            int kMaxBase = 120;  // leaves room for hash + ".c" inside 143
            if (safe.length() > kMaxBase) {
                String hash = String.format("__%08x", demangled.hashCode());
                safe = safe.substring(0, kMaxBase) + hash;
            }
            Path out = outputRoot.resolve(safe + ".c");
            try (BufferedWriter w = Files.newBufferedWriter(out)) {
                w.write("// " + demangled + "\n");
                w.write("// Address (file VMA assuming load=0): 0x" + Long.toHexString(off) + "\n");
                w.write("// Address in this Ghidra project:     0x" + Long.toHexString(off + imageBase) + "\n");
                w.write("\n");
                w.write(code);
            }
            written++;
            if ((written % 10) == 0) {
                long dt = (System.currentTimeMillis() - t0) / 1000;
                println("  decompiled " + written + "/" + addrs.size()
                        + " (failed=" + failed + ", missing=" + missing
                        + ", " + dt + "s elapsed)");
            }
        }
        decomp.dispose();
        long dt = (System.currentTimeMillis() - t0) / 1000;
        println("done: kept=" + kept + " written=" + written
                + " failed=" + failed + " missing=" + missing + " in " + dt + "s");
    }
}
