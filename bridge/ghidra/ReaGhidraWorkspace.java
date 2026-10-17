import com.google.gson.*;
import ghidra.app.util.headless.HeadlessScript;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

/** File-based adapter. A bounded batch shares one JVM, Program and decompiler. */
public class ReaGhidraWorkspace extends HeadlessScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        Path responsePath = Path.of(args[1]);
        JsonObject response;
        end(true);
        try (ReaGhidraReconstruction reconstruction = new ReaGhidraReconstruction()) {
            JsonObject request = JsonParser.parseString(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8)).getAsJsonObject();
            if (!currentProgram.getExecutableSHA256().equalsIgnoreCase(request.get("binary_sha256").getAsString()))
                throw new IllegalArgumentException("Binary digest differs from this project");
            if (request.has("requests")) {
                JsonArray requests = request.getAsJsonArray("requests");
                if (requests.isEmpty() || requests.size() > 256) throw new IllegalArgumentException("A batch requires 1..256 requests");
                JsonArray replies = new JsonArray();
                for (JsonElement item : requests) {
                    monitor.checkCancelled();
                    replies.add(execute(reconstruction, item.getAsJsonObject()));
                }
                response = new JsonObject();
                response.addProperty("ok", true);
                response.add("result", replies);
            } else response = execute(reconstruction, request);
            response.add("statistics", reconstruction.statistics());
        } catch (Exception failure) {
            response = new JsonObject();
            response.addProperty("ok", false);
            response.addProperty("error", failure.toString());
        }
        Files.writeString(responsePath, new GsonBuilder().serializeNulls().create().toJson(response), StandardCharsets.UTF_8,
            StandardOpenOption.CREATE_NEW);
    }

    private JsonObject execute(ReaGhidraReconstruction reconstruction, JsonObject request) {
        JsonObject response = new JsonObject();
        try {
            JsonObject result = reconstruction.execute(currentProgram,
                request.get("method").getAsString(), request.getAsJsonObject("params"), monitor);
            // Each existing-Program edit is saved before its success receipt.
            if (currentProgram.getDomainFile().getParent() != null && currentProgram.isChanged())
                currentProgram.save("REA reconstruction", monitor);
            response.addProperty("ok", true);
            response.add("result", result);
        } catch (Exception failure) {
            response.addProperty("ok", false);
            response.addProperty("error", failure.toString());
        }
        return response;
    }
}
