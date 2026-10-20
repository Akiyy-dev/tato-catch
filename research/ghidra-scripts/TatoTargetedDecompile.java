// Restricted static decompilation of four already validated candidate ranges.
// No client execution, process attachment, profile access, or full auto-analysis.
//@category TatoTalk.Research

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.SourceType;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class TatoTargetedDecompile extends GhidraScript {
    private final long[][] ranges = {
        {0xdb9f80L, 0xdba5caL},
        {0xdb95a0L, 0xdb9f73L},
        {0xe52c40L, 0xe564f8L},
        {0xe52050L, 0xe52c40L}
    };

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("Expected output directory and instruction-start CSV path");
        }
        Path output = Path.of(args[0]);
        Files.createDirectories(output);
        List<String> startLines = Files.readAllLines(Path.of(args[1]), StandardCharsets.UTF_8);
        Address base = currentProgram.getImageBase();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        List<Map<String, Object>> results = new ArrayList<>();
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("program", currentProgram.getName());
        report.put("imageBase", base.toString());
        report.put("mode", "-noanalysis; restricted instruction seeds and restricted function bodies; 45-second decompile limit each");
        report.put("caveat", "Candidate names only. Inferred types and decompiled control flow require validation. No process or client access.");
        report.put("functions", results);

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setOptions(new DecompileOptions());
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Decompiler init failed: " + decompiler.getLastMessage());
            }
            for (long[] range : ranges) {
                monitor.checkCancelled();
                long beginRva = range[0];
                long endRva = range[1];
                Address begin = base.add(beginRva);
                Address end = base.add(endRva - 1);
                AddressSet body = new AddressSet(begin, end);
                AddressSet seeds = new AddressSet();
                for (String line : startLines) {
                    String[] parts = line.split(",");
                    if (parts.length == 2 && Long.parseUnsignedLong(parts[0], 16) == beginRva) {
                        Address seed = base.add(Long.parseUnsignedLong(parts[1], 16));
                        seeds.add(seed);
                    }
                }
                DisassembleCommand command = new DisassembleCommand(seeds, body, false);
                command.enableCodeAnalysis(false);
                boolean disassembled = command.applyTo(currentProgram, monitor);
                String name = "candidate_" + Long.toHexString(beginRva);
                Function function = currentProgram.getFunctionManager().getFunctionAt(begin);
                if (function == null) {
                    function = currentProgram.getFunctionManager().createFunction(name, begin, body, SourceType.USER_DEFINED);
                } else {
                    function.setBody(body);
                }
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("candidateName", name);
                item.put("beginRva", "0x" + Long.toHexString(beginRva));
                item.put("endRvaExclusive", "0x" + Long.toHexString(endRva));
                item.put("entryAddress", begin.toString());
                item.put("disassembleResult", disassembled);
                item.put("disassembleStatus", command.getStatusMsg());
                int instructionCount = 0;
                long instructionBytes = 0;
                List<String> firstInstructions = new ArrayList<>();
                InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    instructionCount++;
                    instructionBytes += instruction.getLength();
                    if (firstInstructions.size() < 45) {
                        firstInstructions.add(instruction.getAddress() + ": " + instruction);
                    }
                }
                item.put("instructionCount", instructionCount);
                item.put("instructionBytes", instructionBytes);
                item.put("rangeBytes", endRva - beginRva);
                item.put("firstInstructions", firstInstructions);
                println("DECOMPILE_START " + name + " instructions=" + instructionCount);
                long started = System.nanoTime();
                DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
                item.put("elapsedSeconds", (System.nanoTime() - started) / 1_000_000_000.0);
                item.put("decompileCompleted", result.decompileCompleted());
                item.put("errorMessage", result.getErrorMessage());
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    String code = result.getDecompiledFunction().getC();
                    Path cPath = output.resolve(name + ".c");
                    Files.writeString(cPath, code, StandardCharsets.UTF_8);
                    item.put("decompiledFile", cPath.toString());
                    item.put("inferredSignature", result.getDecompiledFunction().getSignature());
                    item.put("cCharacterCount", code.length());
                }
                results.add(item);
                Files.writeString(output.resolve("targeted-decompile-report.json"), gson.toJson(report), StandardCharsets.UTF_8);
                println("DECOMPILE_DONE " + name + " completed=" + result.decompileCompleted());
            }
        } finally {
            decompiler.dispose();
        }
    }
}
