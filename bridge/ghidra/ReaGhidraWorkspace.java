import com.google.gson.*;
import ghidra.app.util.headless.HeadlessScript;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

/** File-based adapter for Python/AI clients. Ghidra owns the exclusive project lock. */
public class ReaGhidraWorkspace extends HeadlessScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        Path responsePath = Path.of(args[1]);
        JsonObject response = new JsonObject();
        end(true);
        try {
            JsonObject request = JsonParser.parseString(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8)).getAsJsonObject();
            if (!currentProgram.getExecutableSHA256().equalsIgnoreCase(request.get("binary_sha256").getAsString()))
                throw new IllegalArgumentException("Binary digest differs from this project");
            JsonObject result = ReaGhidraReconstruction.execute(currentProgram,
                request.get("method").getAsString(), request.getAsJsonObject("params"), monitor);
            // Existing programs are checkpointed before success; headless saves new imports on exit.
            if (currentProgram.getDomainFile().getParent() != null && currentProgram.isChanged())
                currentProgram.save("REA reconstruction", monitor);
            response.addProperty("ok", true);
            response.add("result", result);
        } catch (Exception failure) {
            response.addProperty("ok", false);
            response.addProperty("error", failure.toString());
        }
        Files.writeString(responsePath, new GsonBuilder().serializeNulls().create().toJson(response), StandardCharsets.UTF_8,
            StandardOpenOption.CREATE_NEW);
    }
}
