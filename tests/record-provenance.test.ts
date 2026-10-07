import { describe, it, expect, beforeEach } from "vitest";
import {
  RecordProvenanceManager,
  provenanceManager,
  type RecordProvenance,
} from "../lib/record-provenance";

describe("Record Provenance Tracking (#867)", () => {
  let mgr: RecordProvenanceManager;

  beforeEach(() => {
    mgr = new RecordProvenanceManager();
  });

  it("attaches provenance metadata to imported records", () => {
    const rawRecord = { id: "rec-import-001", name: "Imported Vault Config", amount: "5000" };
    const imported = mgr.attachImportProvenance(rawRecord, "batch-2026-09-01", "1.0.0", "operator-alice");

    expect(imported.id).toBe("rec-import-001");
    expect(imported.provenance).toBeDefined();
    expect(imported.provenance.source).toBe("import_batch");
    expect(imported.provenance.importBatchId).toBe("batch-2026-09-01");
    expect(imported.provenance.transformVersion).toBe("1.0.0");
    expect(imported.provenance.actor).toBe("operator-alice");
    expect(imported.provenance.parentDeleted).toBe(false);
  });

  it("traces derived records back to source records", () => {
    const source1 = { id: "src-deposit-101", amount: 100 };
    const source2 = { id: "src-deposit-102", amount: 200 };

    const derived = mgr.attachDerivedProvenance(
      { id: "derived-summary-001", total: 300 },
      [source1, source2],
      "1.1.0",
      "indexer-job"
    );

    expect(derived.provenance.source).toBe("derived_transform");
    expect(derived.provenance.sourceRecordIds).toEqual(["src-deposit-101", "src-deposit-102"]);
    expect(derived.provenance.derivedFrom).toEqual(["src-deposit-101", "src-deposit-102"]);
    expect(derived.provenance.transformVersion).toBe("1.1.0");
    expect(derived.provenance.actor).toBe("indexer-job");
  });

  it("preserves original provenance through updates", () => {
    const original = mgr.attachImportProvenance(
      { id: "rec-005", status: "active" },
      "batch-888",
      "1.0.0",
      "admin-bob"
    );

    const updated = mgr.updateRecordPreservingProvenance(
      original,
      { status: "archived" },
      "operator-charlie"
    );

    expect(updated.status).toBe("archived");
    expect(updated.provenance.importBatchId).toBe("batch-888");
    expect(updated.provenance.actor).toBe("admin-bob"); // Original creator retained
    expect(updated.provenance.history).toHaveLength(2);
    expect(updated.provenance.history?.[1].actor).toBe("operator-charlie");
    expect(updated.provenance.history?.[1].action).toBe("record updated");
  });

  it("handles deleted source records gracefully without severing lineage", () => {
    const source = { id: "source-prize-round-5", prizeAmount: "1000" };
    const derived = mgr.attachDerivedProvenance(
      { id: "derived-claim-999", claimed: true },
      [source],
      "1.0.0",
      "service-bot"
    );

    const updatedDerived = mgr.handleDeletedSourceRecord(derived, "source-prize-round-5", "cleanup-cron");

    expect(updatedDerived.provenance.parentDeleted).toBe(true);
    expect(updatedDerived.provenance.sourceRecordIds).toContain("source-prize-round-5");
    expect(updatedDerived.provenance.history?.some((h) => h.action.includes("deleted"))).toBe(true);
  });

  it("exports a maintainer provenance report with summary and records lineage", () => {
    const rec1 = mgr.attachImportProvenance({ id: "rec-1" }, "b-1", "1.0.0", "admin");
    const rec2 = mgr.attachDerivedProvenance({ id: "rec-2" }, [{ id: "rec-1" }], "1.0.0", "worker");
    const rec2AfterDelete = mgr.handleDeletedSourceRecord(rec2, "rec-1");

    const report = mgr.exportProvenanceReport([rec1, rec2AfterDelete]);

    expect(report.summary.totalRecords).toBe(2);
    expect(report.summary.recordsWithProvenance).toBe(2);
    expect(report.summary.bySource["import_batch"]).toBe(1);
    expect(report.summary.bySource["derived_transform"]).toBe(1);
    expect(report.summary.deletedSourceReferences).toBe(1);
    expect(report.records).toHaveLength(2);
  });

  it("verifies global instance provenanceManager exists", () => {
    expect(provenanceManager).toBeInstanceOf(RecordProvenanceManager);
  });
});
