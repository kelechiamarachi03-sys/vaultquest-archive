/**
 * Record Provenance Tracking (#867).
 *
 * Provides provenance tracking for imported and derived records in VaultQuest.
 * Models source, import batch, transform version, actor metadata, and lineage tracing
 * even when source records are updated or deleted.
 */

export type ProvenanceSourceType =
  | "import_batch"
  | "derived_transform"
  | "migration"
  | "manual_operator"
  | "indexer_replay";

export interface RecordProvenance {
  id: string;
  source: ProvenanceSourceType;
  importBatchId?: string;
  transformVersion: string;
  actor: string;
  timestamp: string;
  sourceRecordIds?: string[];
  derivedFrom?: string[];
  parentDeleted?: boolean;
  history?: Array<{
    updatedAt: string;
    actor: string;
    action: string;
  }>;
}

export interface ProvenanceExportSummary {
  exportedAt: string;
  totalRecords: number;
  recordsWithProvenance: number;
  bySource: Record<string, number>;
  byTransformVersion: Record<string, number>;
  deletedSourceReferences: number;
}

export interface RecordProvenanceReport {
  summary: ProvenanceExportSummary;
  records: Array<{
    recordId: string;
    provenance: RecordProvenance;
  }>;
}

export class RecordProvenanceManager {
  /**
   * Attach provenance metadata to an imported record.
   */
  public attachImportProvenance<T extends { id: string }>(
    record: T,
    importBatchId: string,
    transformVersion: string,
    actor: string
  ): T & { provenance: RecordProvenance } {
    const provenance: RecordProvenance = {
      id: `prov-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      source: "import_batch",
      importBatchId,
      transformVersion,
      actor,
      timestamp: new Date().toISOString(),
      parentDeleted: false,
      history: [
        {
          updatedAt: new Date().toISOString(),
          actor,
          action: `imported in batch ${importBatchId}`,
        },
      ],
    };

    return {
      ...record,
      provenance,
    };
  }

  /**
   * Attach provenance metadata to a derived record created from one or more source records.
   */
  public attachDerivedProvenance<T extends { id: string }, S extends { id: string }>(
    record: T,
    sourceRecords: S[],
    transformVersion: string,
    actor: string
  ): T & { provenance: RecordProvenance } {
    const sourceIds = sourceRecords.map((s) => s.id);
    const provenance: RecordProvenance = {
      id: `prov-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      source: "derived_transform",
      transformVersion,
      actor,
      timestamp: new Date().toISOString(),
      sourceRecordIds: sourceIds,
      derivedFrom: [...sourceIds],
      parentDeleted: false,
      history: [
        {
          updatedAt: new Date().toISOString(),
          actor,
          action: `derived from ${sourceIds.length} source records`,
        },
      ],
    };

    return {
      ...record,
      provenance,
    };
  }

  /**
   * Update a record while preserving its original provenance lineage.
   */
  public updateRecordPreservingProvenance<T extends { id: string; provenance: RecordProvenance }>(
    existingRecord: T,
    updates: Partial<Omit<T, "id" | "provenance">>,
    actor: string
  ): T {
    const now = new Date().toISOString();
    const updatedHistory = [
      ...(existingRecord.provenance.history || []),
      {
        updatedAt: now,
        actor,
        action: "record updated",
      },
    ];

    const updatedProvenance: RecordProvenance = {
      ...existingRecord.provenance,
      history: updatedHistory,
    };

    return {
      ...existingRecord,
      ...updates,
      provenance: updatedProvenance,
    };
  }

  /**
   * Handle deletion of a source record by marking parentDeleted in derived record provenance.
   */
  public handleDeletedSourceRecord<T extends { id: string; provenance: RecordProvenance }>(
    derivedRecord: T,
    deletedSourceId: string,
    actor: string = "system"
  ): T {
    const now = new Date().toISOString();
    const isParent =
      derivedRecord.provenance.sourceRecordIds?.includes(deletedSourceId) ||
      derivedRecord.provenance.derivedFrom?.includes(deletedSourceId);

    if (!isParent) {
      return derivedRecord;
    }

    const updatedHistory = [
      ...(derivedRecord.provenance.history || []),
      {
        updatedAt: now,
        actor,
        action: `source record ${deletedSourceId} was deleted`,
      },
    ];

    return {
      ...derivedRecord,
      provenance: {
        ...derivedRecord.provenance,
        parentDeleted: true,
        history: updatedHistory,
      },
    };
  }

  /**
   * Export maintainer provenance report across a set of domain records.
   */
  public exportProvenanceReport(
    records: Array<{ id: string; provenance?: RecordProvenance }>
  ): RecordProvenanceReport {
    const bySource: Record<string, number> = {};
    const byTransformVersion: Record<string, number> = {};
    let recordsWithProvenance = 0;
    let deletedSourceReferences = 0;

    const reportRecords: Array<{ recordId: string; provenance: RecordProvenance }> = [];

    for (const rec of records) {
      if (rec.provenance) {
        recordsWithProvenance++;
        const p = rec.provenance;
        bySource[p.source] = (bySource[p.source] || 0) + 1;
        byTransformVersion[p.transformVersion] = (byTransformVersion[p.transformVersion] || 0) + 1;

        if (p.parentDeleted) {
          deletedSourceReferences++;
        }

        reportRecords.push({
          recordId: rec.id,
          provenance: p,
        });
      }
    }

    return {
      summary: {
        exportedAt: new Date().toISOString(),
        totalRecords: records.length,
        recordsWithProvenance,
        bySource,
        byTransformVersion,
        deletedSourceReferences,
      },
      records: reportRecords,
    };
  }
}

export const provenanceManager = new RecordProvenanceManager();
