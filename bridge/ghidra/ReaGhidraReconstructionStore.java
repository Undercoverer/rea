import com.google.gson.*;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/** Revision lookup is O(1) after the first successful write migrates a v1 record. */
public final class ReaGhidraReconstructionStore {
    private static final Gson JSON = new Gson();
    private final Options legacy;
    private final Options records;
    private final String key;
    private JsonArray legacyHistory;

    public ReaGhidraReconstructionStore(Program program, String key) {
        legacy = program.getOptions("REA reconstructed source v1");
        records = program.getOptions("REA reconstructed source v2");
        this.key = key;
    }

    public int count() {
        int count = records.getInt("head:" + key, -1);
        if (count >= 0) return count;
        if (legacyHistory == null)
            legacyHistory = JsonParser.parseString(legacy.getString(key, "[]")).getAsJsonArray();
        return legacyHistory.size();
    }

    public JsonObject revision(int number) {
        if (number < 1 || number > count()) throw new IllegalArgumentException("Unknown revision");
        if (records.getInt("head:" + key, -1) < 0)
            return legacyHistory.get(number - 1).getAsJsonObject().deepCopy();
        String value = records.getString("revision:" + key + ":" + number, null);
        if (value == null) throw new IllegalStateException("Missing stored revision " + number);
        return JsonParser.parseString(value).getAsJsonObject();
    }

    public JsonObject latest() { return count() == 0 ? null : revision(count()); }

    /** Caller owns the Program transaction, including migration and rollback. */
    public void append(JsonObject revision) {
        int count = count();
        if (records.getInt("head:" + key, -1) < 0) {
            for (int i = 1; i <= count; i++) put(i, revision(i));
            legacy.removeOption(key);
        }
        put(count + 1, revision);
        records.setInt("head:" + key, count + 1);
    }

    private void put(int number, JsonObject revision) {
        JsonObject stored = revision.deepCopy();
        if (stored.has("changes")) {
            // The source is already stored at the revision root. Full view restores
            // the old wire shape without keeping a second copy in the database.
            stored.getAsJsonObject("changes").remove("source");
        }
        records.setString("revision:" + key + ":" + number, JSON.toJson(stored));
    }

    public JsonArray fullHistory() {
        JsonArray result = new JsonArray();
        for (int i = 1, count = count(); i <= count; i++) {
            JsonObject revision = revision(i);
            if (revision.has("changes")) revision.getAsJsonObject("changes").add("source", revision.get("source"));
            result.add(revision);
        }
        return result;
    }
}
