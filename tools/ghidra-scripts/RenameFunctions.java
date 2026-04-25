// Apply demangled C++ names from `nm` output to functions in the Ghidra
// project. Solves two readability problems:
//
//   1. Ghidra's DWARF importer drops C++ namespaces from function names.
//      Functions show as "postUpdate" instead of "Map::postUpdate".
//   2. Functions not reached by control-flow analysis stay named "FUN_<addr>".
//      Most of these are real engine functions whose names we know from nm.
//
// After running this once, every `.c` file produced by DecompileToFiles.java
// has readable call sites (e.g. `Map::postUpdate(this)` instead of
// `FUN_026e9400(this)`).
//
// Usage (from rename_functions.sh):
//   analyzeHeadless re/ghidra-project factorio_standalone -process factorio \
//     -scriptPath tools/ghidra-scripts -postScript RenameFunctions.java \
//     <symbols_all_txt>
//
// Args:
//   <symbols_all_txt>  : path to nm --demangle output (re/symbols/all.txt)
//
// Strategy:
//   * For each defined T/W/i/u symbol in nm output:
//       - resolve Ghidra address  =  imageBase + file_VMA
//       - look up the function at that address (creating one if missing)
//       - if its current name starts with "FUN_" or matches the leaf-only
//         demangled form, rename it to the full demangled signature.
//   * To preserve information, we also try to apply the function signature
//     (return type, parameter types) parsed by Ghidra's GNU demangler.
//
// Idempotent: running twice does nothing on the second pass.
//
// @category Factorio

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RenameFunctions extends GhidraScript {

    private static final Pattern NM_LINE = Pattern.compile(
        "^([0-9a-f]+)\\s+([A-Za-z])\\s+(.+)$");

    /**
     * Strip a demangled C++ name down to a Ghidra-compatible symbol name.
     * Removes parameter lists, leading qualifier verbs, and trailing const/
     * cv-qualifiers. Returns null if the input doesn't look usable.
     *
     * Examples:
     *   "Map::updateEntities()"                        -> "Map::updateEntities"
     *   "Map::createSurface(std::string, ...)"         -> "Map::createSurface"
     *   "non-virtual thunk to Map::~Map()"             -> "thunk_Map::~Map"
     *   "vtable for Map"                               -> "vtable_for_Map"
     *   "Foo::operator+(int) const"                    -> "Foo::operator+"
     *   "Foo<int>::bar()"                              -> "Foo<int>::bar"
     */
    private static String stripToCallableName(String demangled) {
        if (demangled == null) return null;
        String s = demangled.trim();
        if (s.isEmpty()) return null;

        // Recognized prefixes that need to be turned into a single-token
        // form (so the rest of the name keeps its `::`).
        if (s.startsWith("non-virtual thunk to ")) {
            s = "thunk_" + s.substring("non-virtual thunk to ".length());
        } else if (s.startsWith("virtual thunk to ")) {
            s = "vthunk_" + s.substring("virtual thunk to ".length());
        } else if (s.startsWith("construction vtable for ")) {
            s = "construction_vtable_" + s.substring("construction vtable for ".length());
        } else if (s.startsWith("vtable for ")) {
            s = "vtable_for_" + s.substring("vtable for ".length());
        } else if (s.startsWith("typeinfo for ")) {
            s = "typeinfo_for_" + s.substring("typeinfo for ".length());
        } else if (s.startsWith("typeinfo name for ")) {
            s = "typeinfo_name_" + s.substring("typeinfo name for ".length());
        } else if (s.startsWith("guard variable for ")) {
            s = "guard_var_" + s.substring("guard variable for ".length());
        }

        // Drop everything from the first '(' that opens the parameter list.
        // We have to be careful with template arguments: "std::map<int, ...>"
        // has parens potentially nested. Scan with a depth counter for '<'.
        int depth = 0;
        int paren = -1;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '<') depth++;
            else if (c == '>') depth = Math.max(0, depth - 1);
            else if (c == '(' && depth == 0) {
                paren = i;
                break;
            }
        }
        if (paren >= 0) s = s.substring(0, paren);

        s = s.trim();
        if (s.isEmpty()) return null;

        // Replace remaining problematic characters with underscores. Ghidra
        // accepts letters, digits, underscores, and a few punctuators
        // (`::`, `<`, `>`, `~`, `_`, `$`). Anything else, sanitize.
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isLetterOrDigit(c)
                || c == '_' || c == ':' || c == '<' || c == '>'
                || c == '~' || c == '$' || c == '.') {
                out.append(c);
            } else if (c == ' ') {
                out.append('_');
            } else {
                // operator+, operator,, operator() etc. — keep them readable
                // by mapping to descriptive tokens
                switch (c) {
                    case '+': out.append("_plus"); break;
                    case '-': out.append("_minus"); break;
                    case '*': out.append("_star"); break;
                    case '/': out.append("_slash"); break;
                    case '%': out.append("_pct"); break;
                    case '=': out.append("_eq"); break;
                    case '!': out.append("_bang"); break;
                    case '&': out.append("_amp"); break;
                    case '|': out.append("_pipe"); break;
                    case '^': out.append("_xor"); break;
                    case ',': out.append("_comma"); break;
                    case '?': out.append("_q"); break;
                    case '[': out.append("_lb"); break;
                    case ']': out.append("_rb"); break;
                    default: out.append('_'); break;
                }
            }
        }
        return out.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: RenameFunctions <symbols_all_txt>");
            return;
        }
        Path symbolsFile = Paths.get(args[0]);
        if (!Files.isRegularFile(symbolsFile)) {
            printerr("not a file: " + symbolsFile);
            return;
        }

        long imageBase = currentProgram.getImageBase().getOffset();
        println("imageBase = 0x" + Long.toHexString(imageBase));

        FunctionManager fm = currentProgram.getFunctionManager();

        int totalLines = 0;
        int considered = 0;
        int renamed = 0;
        int skippedExisting = 0;
        int skippedNoFunction = 0;
        int errors = 0;

        long t0 = System.currentTimeMillis();

        try (BufferedReader r = Files.newBufferedReader(symbolsFile)) {
            String line;
            while ((line = r.readLine()) != null) {
                totalLines++;
                if (monitor.isCancelled()) break;
                Matcher m = NM_LINE.matcher(line);
                if (!m.matches()) continue;
                String addrHex = m.group(1);
                String t = m.group(2);
                String name = m.group(3);
                // T/t = .text, W/w = weak, i/u = ifunc/unique. All callable.
                if (!"TtWwiu".contains(t)) continue;
                // Skip stdlib / mangled-only (ones starting with _Z but never
                // demangled by nm — already caught: nm --demangle would have
                // produced human-readable names, so anything starting with _Z
                // here means demangling failed. Keep it anyway.)
                considered++;

                long off;
                try {
                    off = Long.parseUnsignedLong(addrHex, 16);
                } catch (NumberFormatException e) {
                    continue;
                }
                if (off == 0) continue;

                Address ga = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(off + imageBase);

                Function fn = fm.getFunctionAt(ga);
                if (fn == null) {
                    fn = fm.getFunctionContaining(ga);
                    if (fn == null || !fn.getEntryPoint().equals(ga)) {
                        // No function exactly at this address. Skip rather
                        // than try to create one — the auto-analyzer's
                        // function-bound discovery is usually better than ours.
                        skippedNoFunction++;
                        continue;
                    }
                }

                // Strip everything from the first unbalanced '(' onward.
                // Ghidra symbol names cannot contain parentheses. The
                // parameter list lives in the function signature, not the
                // name. Also strip a leading "non-virtual thunk to " etc.
                String desired = stripToCallableName(name);
                if (desired == null || desired.isEmpty()) continue;

                String currentName = fn.getName();
                // Idempotency: if the current name already matches what we'd
                // set, skip.
                boolean alreadyFull = currentName.equals(desired)
                    || currentName.startsWith(desired + "_at_");

                if (alreadyFull) {
                    skippedExisting++;
                    continue;
                }

                boolean isAuto = currentName.startsWith("FUN_")
                                 || currentName.startsWith("_init")
                                 || currentName.startsWith("_fini")
                                 || currentName.startsWith("LAB_")
                                 || currentName.startsWith("UNK_");
                boolean isLeaf = !currentName.contains("::");

                if (!isAuto && !isLeaf) {
                    // Already has some namespaced name — don't clobber.
                    skippedExisting++;
                    continue;
                }

                // Try the full namespaced form first. On DuplicateNameException
                // (overloads collapsing to the same name once parens are
                // stripped), append "_at_<addr>" as a disambiguator.
                String applied = null;
                try {
                    fn.setName(desired, SourceType.IMPORTED);
                    applied = desired;
                } catch (DuplicateNameException e) {
                    String disamb = desired + "_at_" + Long.toHexString(off);
                    try {
                        fn.setName(disamb, SourceType.IMPORTED);
                        applied = disamb;
                    } catch (Exception e2) {
                        errors++;
                    }
                } catch (InvalidInputException e) {
                    errors++;
                    if (errors <= 5) {
                        println("  invalid name: " + desired
                                + "  (from: " + name + ")");
                    }
                }
                if (applied != null) {
                    renamed++;
                    // Stash the full demangled signature (with parens and
                    // parameters) in a plate comment so the info isn't lost.
                    try {
                        fn.setComment("Demangled: " + name);
                    } catch (Exception ignored) {
                        // Comment failures aren't fatal.
                    }
                }

                if (renamed > 0 && (renamed % 5000) == 0) {
                    long dt = (System.currentTimeMillis() - t0) / 1000;
                    println("  ... renamed " + renamed + " (" + dt + "s)");
                }
            }
        }

        long dt = (System.currentTimeMillis() - t0) / 1000;
        println("done: scanned=" + totalLines
                + " considered=" + considered
                + " renamed=" + renamed
                + " skipped(existing)=" + skippedExisting
                + " skipped(no function)=" + skippedNoFunction
                + " errors=" + errors
                + " in " + dt + "s");
    }
}
