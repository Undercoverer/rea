import com.google.gson.*;
import ghidra.app.script.GhidraScript;

/** Real Program regression for legacy history migration and transaction rollback. */
public class ReaReconstructionMigrationTest extends GhidraScript {
    public void run() throws Exception {
        var function = currentProgram.getFunctionManager().getFunctions(true).next();
        String address = function.getEntryPoint().toString(true);
        JsonObject old = new JsonObject();
        old.addProperty("revision", 1);
        old.addProperty("source", "int old(void) { return 1; }");
        old.addProperty("summary", "legacy");
        old.addProperty("name", function.getName());
        old.addProperty("signature", function.getSignature().getPrototypeString());
        JsonObject changes = new JsonObject(); changes.add("source", old.get("source")); old.add("changes", changes);
        JsonArray history = new JsonArray(); history.add(old);
        var legacy = currentProgram.getOptions("REA reconstructed source v1");
        legacy.setString(address, history.toString());
        // End GhidraScript's ambient transaction so rollback below is meaningful.
        end(true);
        var store = new ReaGhidraReconstructionStore(currentProgram, address);
        if (store.count() != 1) throw new AssertionError("Legacy read failed");
        int transaction = currentProgram.startTransaction("rollback migration");
        store.append(old);
        currentProgram.endTransaction(transaction, false);
        store = new ReaGhidraReconstructionStore(currentProgram, address);
        if (store.count() != 1 || legacy.getString(address, null) == null) throw new AssertionError("Rollback lost legacy data");
        transaction = currentProgram.startTransaction("migrate");
        JsonObject next = old.deepCopy(); next.addProperty("revision", 2); next.addProperty("source", "int new_source(void) { return 2; }");
        store.append(next);
        currentProgram.endTransaction(transaction, true);
        store = new ReaGhidraReconstructionStore(currentProgram, address);
        if (store.count() != 2 || legacy.getString(address, null) != null) throw new AssertionError("Migration failed");
        if (!store.revision(1).get("source").equals(old.get("source"))) throw new AssertionError("Old source changed");
        if (store.revision(1).getAsJsonObject("changes").has("source")) throw new AssertionError("Duplicate source retained");
        if (!store.fullHistory().get(0).getAsJsonObject().getAsJsonObject("changes").has("source")) throw new AssertionError("Full view lost compatibility");
        println("REA_MIGRATION_TEST_PASSED");
    }
}
