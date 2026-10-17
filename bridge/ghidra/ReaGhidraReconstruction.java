import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

/** Address-owned source with producer-side context selection and session-only reuse. */
public final class ReaGhidraReconstruction implements AutoCloseable {
    private static final Gson JSON = new GsonBuilder().serializeNulls().create();
    // Memory ceiling for retained UTF-16 decompiler text, never a source truncation limit.
    private static final long CACHE_BYTES = 16L * 1024 * 1024;
    private final LinkedHashMap<String, String> cache = new LinkedHashMap<>(16, .75f, true);
    private long cacheBytes;
    private long modification = -1;
    private Program owner;
    private DecompInterface decompiler;
    private long decompileCalls;
    private long cacheHits;

    public JsonObject execute(Program program, String method, JsonObject request,
            TaskMonitor monitor) throws Exception {
        if (method.equals("list_reconstructions")) return list(program, request, monitor);
        boolean write = method.equals("write_reconstruction");
        boolean history = method.equals("read_reconstruction_history");
        if (!write && !history && !method.equals("read_reconstruction"))
            throw new IllegalArgumentException("Unknown reconstruction method");
        Set<String> fields = history ? Set.of("address", "offset", "limit", "include_source") : write ?
            Set.of("address", "expected_revision", "expected_context_hash", "source", "summary", "signature", "name", "comment", "declarations", "view") :
            Set.of("address", "view");
        requireFields(request, fields);
        Address address = program.getAddressFactory().getAddress(text(request, "address"));
        Function function = address == null ? null : program.getFunctionManager().getFunctionAt(address);
        if (function == null || function.isExternal()) throw new IllegalArgumentException("A local function entry address is required");
        var store = store(program, function);
        if (history) return history(store, function, request, monitor);
        String view = request.has("view") ? text(request, "view") : "full";
        if (!Set.of("full", "context", "receipt").contains(view) || (!write && view.equals("receipt")))
            throw new IllegalArgumentException("Unsupported reconstruction view");
        JsonObject before = null;
        boolean metadata = false;
        if (write) {
            if (integer(request, "expected_revision", -1, 0, Integer.MAX_VALUE) != store.count())
                throw new IllegalArgumentException("Revision conflict: read the latest reconstruction before editing");
            String source = text(request, "source");
            if (request.has("expected_context_hash")) {
                before = context(program, function, store, null, monitor);
                if (!text(request, "expected_context_hash").equals(text(before, "context_hash")))
                    throw new IllegalArgumentException("Context conflict: live analysis or dependencies changed; read again");
            }
            metadata = List.of("signature", "name", "comment", "declarations").stream().anyMatch(request::has);
            int transaction = program.startTransaction("REA reconstruction revision");
            boolean commit = false;
            try {
                if (request.has("declarations")) {
                    CParser parser = new CParser(program.getDataTypeManager());
                    parser.parse(new java.io.ByteArrayInputStream(text(request, "declarations").getBytes(StandardCharsets.UTF_8)));
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
                revision.addProperty("revision", store.count() + 1);
                revision.addProperty("created_at", Instant.now().toString());
                revision.addProperty("source", source);
                revision.addProperty("summary", request.has("summary") ? text(request, "summary") : "");
                revision.addProperty("signature", function.getSignature().getPrototypeString());
                revision.addProperty("name", function.getName());
                JsonObject changes = request.deepCopy();
                changes.remove("view");
                changes.remove("expected_context_hash");
                revision.add("changes", changes);
                store.append(revision);
                commit = true;
            } finally { program.endTransaction(transaction, commit); }
        }
        // A source-only transaction cannot change decompiled instructions. Reuse only
        // the observation validated immediately before that transaction, not a disk cache.
        String raw = write && !metadata && before != null ?
            (before.has("decompiled_source") ? text(before, "decompiled_source") : text(before, "source")) : null;
        if (view.equals("context") || (view.equals("receipt") && before != null)) {
            JsonObject context = context(program, function, store, raw, monitor);
            if (view.equals("context")) return context;
            JsonObject receipt = identity(program, function, store);
            receipt.add("context_hash", context.get("context_hash"));
            receipt.add("source_sha256", context.get("source_sha256"));
            return receipt;
        }
        JsonObject result = identity(program, function, store);
        if (view.equals("receipt")) return result;
        result.add("history", store.fullHistory());
        JsonObject latest = store.latest();
        result.add("source", latest == null ? JsonNull.INSTANCE : latest.get("source"));
        result.addProperty("metadata_changed_since_revision", latest != null &&
            (!text(latest, "signature").equals(function.getSignature().getPrototypeString()) ||
             !text(latest, "name").equals(function.getName())));
        try {
            result.addProperty("decompiled_source", raw == null ? decompile(program, function, monitor) : raw);
            result.add("decompiler_error", JsonNull.INSTANCE);
        } catch (DecompileFailure failure) {
            result.add("decompiled_source", JsonNull.INSTANCE);
            result.addProperty("decompiler_error", failure.getMessage());
        }
        return result;
    }

    private JsonObject context(Program program, Function function, ReaGhidraReconstructionStore store,
            String observedRaw, TaskMonitor monitor) throws Exception {
        String raw = observedRaw == null ? decompile(program, function, monitor) : observedRaw;
        JsonObject result = identity(program, function, store);
        result.addProperty("context_version", 1);
        result.addProperty("ghidra_version", Application.getApplicationVersion());
        result.addProperty("language", program.getLanguageID().toString());
        result.addProperty("compiler_spec", program.getCompilerSpec().getCompilerSpecID().toString());
        JsonObject latest = store.latest();
        String source = latest == null ? raw : text(latest, "source");
        result.addProperty("source", source);
        result.addProperty("source_origin", latest == null ? "decompiler" : "reconstruction");
        result.addProperty("source_sha256", hash(source));
        // Preserve live evidence when it differs, without repeating identical text.
        if (!source.equals(raw)) result.addProperty("decompiled_source", raw);
        result.addProperty("summary", latest == null ? "" : text(latest, "summary"));
        result.addProperty("history_count", store.count());
        JsonArray callees = new JsonArray();
        List<Function> ordered = new ArrayList<>(function.getCalledFunctions(monitor));
        ordered.sort(Comparator.comparing(Function::getEntryPoint));
        for (Function callee : ordered) {
            monitor.checkCancelled();
            JsonObject entry = new JsonObject();
            entry.addProperty("address", callee.getEntryPoint().toString(true));
            entry.addProperty("name", callee.getName(true));
            entry.addProperty("signature", callee.getSignature().getPrototypeString());
            entry.addProperty("comment", callee.getComment());
            entry.addProperty("external", callee.isExternal());
            var calleeStore = store(program, callee);
            entry.addProperty("revision", calleeStore.count());
            JsonObject last = calleeStore.latest();
            if (last != null) entry.add("summary", last.get("summary"));
            callees.add(entry);
        }
        result.add("callees", callees);
        result.addProperty("dependency_coverage", "Ghidra-observed direct callees; indirect/runtime dependencies may be unresolved");
        result.addProperty("context_hash", hash(JSON.toJson(result)));
        return result;
    }

    private String decompile(Program program, Function function, TaskMonitor monitor) throws Exception {
        if (owner != program) {
            close();
            owner = program;
            decompiler = new DecompInterface();
            if (!decompiler.openProgram(program)) throw new IllegalStateException("Cannot open decompiler");
        }
        long current = program.getModificationNumber();
        if (modification != current) {
            cache.clear(); cacheBytes = 0;
            decompiler.flushCache();
            modification = current;
        }
        String key = function.getEntryPoint().toString(true);
        String found = cache.get(key);
        if (found != null) { cacheHits++; return found; }
        decompileCalls++;
        var result = decompiler.decompileFunction(function, 60, monitor);
        monitor.checkCancelled();
        if (!result.decompileCompleted() || result.getDecompiledFunction() == null)
            throw new DecompileFailure(result.getErrorMessage());
        String source = result.getDecompiledFunction().getC();
        // Never cache an observation across a concurrent Program edit.
        if (current != program.getModificationNumber())
            throw new IllegalStateException("Program changed during decompilation; retry");
        long bytes = 2L * source.length();
        if (bytes <= CACHE_BYTES) {
            while (cacheBytes + bytes > CACHE_BYTES && !cache.isEmpty()) {
                var iterator = cache.entrySet().iterator();
                cacheBytes -= 2L * iterator.next().getValue().length(); iterator.remove();
            }
            cache.put(key, source); cacheBytes += bytes;
        }
        return source;
    }

    private static JsonObject identity(Program program, Function function, ReaGhidraReconstructionStore store) {
        JsonObject value = new JsonObject();
        value.addProperty("address", function.getEntryPoint().toString(true));
        value.addProperty("binary_sha256", program.getExecutableSHA256());
        value.addProperty("revision", store.count());
        value.addProperty("name", function.getName());
        value.addProperty("signature", function.getSignature().getPrototypeString());
        value.addProperty("comment", function.getComment());
        value.addProperty("machine_code_modified", false);
        return value;
    }

    private static JsonObject history(ReaGhidraReconstructionStore store, Function function,
            JsonObject request, TaskMonitor monitor) throws Exception {
        int offset = integer(request, "offset", 0, 0, Integer.MAX_VALUE);
        int limit = integer(request, "limit", 20, 1, 1000);
        boolean source = bool(request, "include_source", false);
        JsonObject result = new JsonObject();
        result.addProperty("address", function.getEntryPoint().toString(true));
        result.addProperty("total", store.count());
        result.addProperty("offset", offset);
        JsonArray revisions = new JsonArray();
        int end = (int)Math.min((long)store.count(), (long)offset + limit);
        for (int i = offset; i < end; i++) {
            monitor.checkCancelled();
            JsonObject revision = store.revision(i + 1);
            if (!source) { revision.remove("source"); revision.remove("changes"); }
            revisions.add(revision);
        }
        result.add("revisions", revisions);
        result.add("next_offset", end < store.count() ? new JsonPrimitive(end) : JsonNull.INSTANCE);
        return result;
    }

    private static JsonObject list(Program program, JsonObject request, TaskMonitor monitor) throws Exception {
        requireFields(request, Set.of("after", "limit"));
        int limit = integer(request, "limit", 100, 1, 1000);
        Address after = request.has("after") ? program.getAddressFactory().getAddress(text(request, "after")) : null;
        if (request.has("after") && after == null) throw new IllegalArgumentException("Invalid function cursor");
        var functions = after == null ? program.getFunctionManager().getFunctions(true) : program.getFunctionManager().getFunctions(after, true);
        JsonArray page = new JsonArray();
        String last = null;
        boolean more = false;
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            if (function.isExternal() || (after != null && function.getEntryPoint().compareTo(after) <= 0)) continue;
            if (page.size() == limit) { more = true; break; }
            last = function.getEntryPoint().toString(true);
            JsonObject row = identity(program, function, store(program, function));
            row.remove("binary_sha256"); row.remove("machine_code_modified"); row.remove("comment");
            page.add(row);
        }
        JsonObject result = new JsonObject();
        result.addProperty("binary_sha256", program.getExecutableSHA256());
        result.add("functions", page);
        result.add("next_after", more ? new JsonPrimitive(last) : JsonNull.INSTANCE);
        return result;
    }

    public JsonObject statistics() {
        JsonObject result = new JsonObject();
        result.addProperty("decompile_calls", decompileCalls);
        result.addProperty("cache_hits", cacheHits);
        result.addProperty("cached_utf16_bytes", cacheBytes);
        return result;
    }

    @Override public void close() {
        if (decompiler != null) decompiler.dispose();
        decompiler = null; owner = null; modification = -1; cache.clear(); cacheBytes = 0;
    }

    private static ReaGhidraReconstructionStore store(Program program, Function function) {
        return new ReaGhidraReconstructionStore(program, function.getEntryPoint().toString(true));
    }
    private static void requireFields(JsonObject request, Set<String> fields) {
        if (!fields.containsAll(request.keySet())) throw new IllegalArgumentException("Unknown reconstruction field");
    }
    private static String text(JsonObject request, String field) {
        JsonElement value = request.get(field);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString())
            throw new IllegalArgumentException(field + " must be a string");
        return value.getAsString();
    }
    private static int integer(JsonObject request, String field, int fallback, int min, int max) {
        if (!request.has(field)) {
            if (fallback < min) throw new IllegalArgumentException(field + " is required");
            return fallback;
        }
        JsonElement value = request.get(field);
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber() || !value.getAsString().matches("0|[1-9][0-9]*"))
            throw new IllegalArgumentException(field + " must be an integer");
        long number;
        try { number = Long.parseLong(value.getAsString()); }
        catch (NumberFormatException failure) { throw new IllegalArgumentException(field + " is out of range"); }
        if (number < min || number > max) throw new IllegalArgumentException(field + " is out of range");
        return (int)number;
    }
    private static boolean bool(JsonObject request, String field, boolean fallback) {
        if (!request.has(field)) return fallback;
        JsonElement value = request.get(field);
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) throw new IllegalArgumentException(field + " must be a boolean");
        return value.getAsBoolean();
    }
    private static String hash(String source) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(source.getBytes(StandardCharsets.UTF_8)));
    }
    private static final class DecompileFailure extends Exception {
        DecompileFailure(String message) { super(message); }
    }
}
