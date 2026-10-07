import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  SensitiveFieldAccessLogger,
  SENSITIVE_FIELDS,
  sensitiveAccessLogger,
  type AnomalyEvent,
} from "../lib/sensitive-field-access";

describe("SensitiveFieldAccessLogger (#868)", () => {
  let logger: SensitiveFieldAccessLogger;

  beforeEach(() => {
    logger = new SensitiveFieldAccessLogger({
      maxDeniedAttemptsInWindow: 2,
      maxRapidResourcesInWindow: 3,
      bulkFieldThreshold: 4,
      windowMs: 60000,
    });
  });

  it("identifies sensitive field names", () => {
    expect(logger.isSensitiveField("ssn")).toBe(true);
    expect(logger.isSensitiveField("wallet_seed")).toBe(true);
    expect(logger.isSensitiveField("user_secret_token")).toBe(true);
    expect(logger.isSensitiveField("public_name")).toBe(false);
  });

  it("logs authorized access without storing sensitive field values (redaction)", () => {
    const entry = logger.logAccess({
      actor: "admin-001",
      purpose: "vault_audit",
      resourceType: "vault",
      resourceId: "vault-123",
      fieldNames: ["secret", "email"],
      authorized: true,
      rawValues: { secret: "SUPER_SECRET_KEY_123", email: "user@example.com" },
    });

    expect(entry.id).toBeDefined();
    expect(entry.actor).toBe("admin-001");
    expect(entry.purpose).toBe("vault_audit");
    expect(entry.resourceType).toBe("vault");
    expect(entry.resourceId).toBe("vault-123");
    expect(entry.fields).toEqual(["secret", "email"]);
    expect(entry.authorized).toBe(true);
    expect(entry.redacted).toBe(true);
    // Ensure raw values were NOT retained in the entry
    expect((entry as Record<string, unknown>).rawValues).toBeUndefined();
    expect(JSON.stringify(entry)).not.toContain("SUPER_SECRET_KEY_123");
  });

  it("safely captures unauthorized access attempts", () => {
    const entry = logger.logAccess({
      actor: "untrusted-user",
      purpose: "unauthorized_export",
      resourceType: "user_profile",
      resourceId: "user-456",
      fieldNames: ["ssn", "tax_id"],
      authorized: false,
      ipAddress: "192.168.1.50",
    });

    expect(entry.authorized).toBe(false);
    expect(entry.actor).toBe("untrusted-user");
    expect(entry.ipAddress).toBe("192.168.1.50");

    const logs = logger.queryLogs({ authorized: false });
    expect(logs).toHaveLength(1);
    expect(logs[0].id).toBe(entry.id);
  });

  it("identifies bulk access queries", () => {
    const bulkEntry = logger.logAccess({
      actor: "auditor-01",
      purpose: "compliance_check",
      resourceType: "account",
      resourceId: "acc-999",
      fieldNames: ["ssn", "tax_id", "private_key", "secret", "vault_pin"],
      authorized: true,
    });

    expect(bulkEntry.bulk).toBe(true);
    expect(bulkEntry.fields).toHaveLength(5);
  });

  it("triggers anomaly hooks on unauthorized bulk access and threshold breaches", () => {
    const anomalyCallback = vi.fn();
    logger.onAnomaly(anomalyCallback);

    // 1. Unauthorized bulk access triggers immediate anomaly hook
    logger.logAccess({
      actor: "attacker-x",
      purpose: "dump",
      resourceType: "vault",
      resourceId: "vault-777",
      fieldNames: ["private_key", "wallet_seed", "secret", "vault_pin"],
      authorized: false,
    });

    expect(anomalyCallback).toHaveBeenCalled();
    const anomalyArg: AnomalyEvent = anomalyCallback.mock.calls[0][0];
    expect(anomalyArg.rule).toBe("UNAUTHORIZED_BULK_ACCESS");
    expect(anomalyArg.severity).toBe("critical");
    expect(anomalyArg.actor).toBe("attacker-x");
  });

  it("evaluates windowed access patterns for burst denied access anomalies", () => {
    const anomalyCallback = vi.fn();
    logger.onAnomaly(anomalyCallback);

    logger.logAccess({
      actor: "suspicious-actor",
      purpose: "probe-1",
      resourceType: "vault",
      resourceId: "v1",
      fieldNames: ["ssn"],
      authorized: false,
    });

    logger.logAccess({
      actor: "suspicious-actor",
      purpose: "probe-2",
      resourceType: "vault",
      resourceId: "v2",
      fieldNames: ["ssn"],
      authorized: false,
    });

    const anomalies = logger.evaluateAnomalies();
    expect(anomalies.some((a) => a.rule === "UNAUTHORIZED_BURST")).toBe(true);
  });

  it("verifies global instance sensitiveAccessLogger exists", () => {
    expect(sensitiveAccessLogger).toBeInstanceOf(SensitiveFieldAccessLogger);
  });
});
