import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.time.Instant;
import java.util.Set;

/** Address-owned reconstructed source, distinct from executable instructions. */
public final class ReaGhidraReconstruction {
    private static final Gson JSON = new Gson();
    private static final String STORE = "REA reconstructed source v1";

    public static JsonObject execute(Program program, String method, JsonObject request,
            TaskMonitor monitor) throws Exception {
        if (!Set.of("read_reconstruction", "write_reconstruction").contains(method))
            throw new IllegalArgumentException("Unknown reconstruction method");
        Set<String> fields = method.equals("read_reconstruction") ? Set.of("address") :
            Set.of("address", "expected_revision", "source", "summary", "signature", "name", "comment", "declarations");
        if (!fields.containsAll(request.keySet())) throw new IllegalArgumentException("Unknown reconstruction field");
        String address = text(request, "address");
        Function function = program.getFunctionManager().getFunctionAt(
            program.getAddressFactory().getAddress(address));
        if (function == null || function.isExternal())
            throw new IllegalArgumentException("A local function entry address is required");
        String key = function.getEntryPoint().toString(true);
        var options = program.getOptions(STORE);
        JsonArray history = JsonParser.parseString(options.getString(key, "[]")).getAsJsonArray();
        if (method.equals("write_reconstruction")) {
            JsonElement expected = request.get("expected_revision");
            if (expected == null || !expected.isJsonPrimitive() || !expected.getAsJsonPrimitive().isNumber()
                    || !expected.getAsString().matches("0|[1-9][0-9]*") || expected.getAsLong() != history.size())
                throw new IllegalArgumentException("Revision conflict: read the latest reconstruction before editing");
            String source = text(request, "source");
            // Full source is analyst/AI-authored text. Only explicit metadata is applied to Ghidra.
            int transaction = program.startTransaction("REA reconstruction revision");
            boolean commit = false;
            try {
                if (request.has("declarations")) {
                    CParser parser = new CParser(program.getDataTypeManager());
                    parser.parse(new java.io.ByteArrayInputStream(text(request, "declarations")
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                    if (!parser.didParseSucceed()) throw new IllegalArgumentException(parser.getParseMessages());
                }
                if (request.has("signature")) {
                    var signature = new FunctionSignatureParser(program.getDataTypeManager(), null)
                        .parse(function.getSignature(), text(request, "signature"));
                    var command = new ApplyFunctionSignatureCmd(function.getEntryPoint(), signature, SourceType.USER_DEFINED);
                    if (!command.applyTo(program, monitor)) throw new IllegalArgumentException(command.getStatusMsg());
                }
                if (request.has("name")) function.setName(text(request, "name"), SourceType.USER_DEFINED);
                if (request.has("comment")) function.setComment(text(request, "comment"));
                monitor.checkCancelled();
                JsonObject revision = new JsonObject();
                revision.addProperty("revision", history.size() + 1);
                revision.addProperty("created_at", Instant.now().toString());
                revision.addProperty("source", source);
                revision.addProperty("summary", request.has("summary") ? text(request, "summary") : "");
                revision.addProperty("signature", function.getSignature().getPrototypeString());
                revision.addProperty("name", function.getName());
                revision.add("changes", request.deepCopy());
                history.add(revision);
                options.setString(key, JSON.toJson(history));
                commit = true;
            } finally { program.endTransaction(transaction, commit); }
        }
        JsonObject result = new JsonObject();
        result.addProperty("address", key);
        result.addProperty("binary_sha256", program.getExecutableSHA256());
        result.addProperty("revision", history.size());
        result.addProperty("name", function.getName());
        result.addProperty("signature", function.getSignature().getPrototypeString());
        result.addProperty("comment", function.getComment());
        result.add("history", history);
        result.add("source", history.isEmpty() ? JsonNull.INSTANCE : history.get(history.size()-1).getAsJsonObject().get("source"));
        result.addProperty("metadata_changed_since_revision", !history.isEmpty() &&
            (!history.get(history.size()-1).getAsJsonObject().get("signature").getAsString().equals(function.getSignature().getPrototypeString()) ||
             !history.get(history.size()-1).getAsJsonObject().get("name").getAsString().equals(function.getName())));
        result.addProperty("machine_code_modified", false);
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(program)) throw new IllegalStateException("Cannot open decompiler");
            var decompiled = decompiler.decompileFunction(function, 60, monitor);
            result.addProperty("decompiled_source", decompiled.decompileCompleted() ?
                decompiled.getDecompiledFunction().getC() : null);
            result.addProperty("decompiler_error", decompiled.decompileCompleted() ? null : decompiled.getErrorMessage());
        } finally { decompiler.dispose(); }
        return result;
    }

    private static String text(JsonObject request, String field) {
        JsonElement value = request.get(field);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())
            throw new IllegalArgumentException(field + " must be a string");
        return value.getAsString();
    }
}
