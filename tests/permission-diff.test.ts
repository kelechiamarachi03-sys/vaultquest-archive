import { describe, it, expect } from "vitest";
import {
  computePermissionDiff,
  PermissionDiffDeniedError,
  StalePolicyInputError,
  type RolePolicy,
} from "../lib/permission-diff";
import { ROLE_PERMISSIONS } from "../lib/rbac";

describe("Permission Diff Preview (#863)", () => {
  const basePolicy: RolePolicy = {
    version: 1,
    roles: {
      user: [...ROLE_PERMISSIONS.user],
      maintainer: [...ROLE_PERMISSIONS.maintainer],
      service: [...ROLE_PERMISSIONS.service],
    },
  };

  it("handles a no-op change (no permission added or removed)", () => {
    const proposedPolicy: RolePolicy = {
      version: 2,
      roles: {
        user: [...ROLE_PERMISSIONS.user],
        maintainer: [...ROLE_PERMISSIONS.maintainer],
        service: [...ROLE_PERMISSIONS.service],
      },
    };

    const preview = computePermissionDiff({
      actorRoles: ["maintainer"],
      currentPolicy: basePolicy,
      proposedPolicy,
    });

    expect(preview.isNoOp).toBe(true);
    expect(preview.requiresConfirmation).toBe(false);
    expect(preview.summary.totalAdded).toBe(0);
    expect(preview.summary.totalRemoved).toBe(0);
    expect(preview.summary.rolesModified).toEqual([]);
  });

  it("computes narrow changes without requiring broad confirmation", () => {
    const proposedPolicy: RolePolicy = {
      version: 2,
      roles: {
        ...basePolicy.roles,
        user: [...basePolicy.roles.user, "admin.receipts.read"],
      },
    };

    const preview = computePermissionDiff({
      actorRoles: ["maintainer"],
      currentPolicy: basePolicy,
      proposedPolicy,
    });

    expect(preview.isNoOp).toBe(false);
    expect(preview.requiresConfirmation).toBe(false);
    expect(preview.summary.totalAdded).toBe(1);
    expect(preview.summary.totalRemoved).toBe(0);
    expect(preview.summary.rolesModified).toEqual(["user"]);

    const userDiff = preview.diffs.find((d) => d.role === "user");
    expect(userDiff?.addedPermissions).toEqual(["admin.receipts.read"]);
  });

  it("flags broad changes and requires explicit confirmation when granting critical permissions to user role", () => {
    const proposedPolicy: RolePolicy = {
      version: 2,
      roles: {
        ...basePolicy.roles,
        user: [...basePolicy.roles.user, "admin.audit.write"],
      },
    };

    const preview = computePermissionDiff({
      actorRoles: ["maintainer"],
      currentPolicy: basePolicy,
      proposedPolicy,
    });

    expect(preview.isNoOp).toBe(false);
    expect(preview.isBroadChange).toBe(true);
    expect(preview.requiresConfirmation).toBe(true);
    expect(preview.confirmationReason).toContain("Granting critical administrative permission");
  });

  it("throws PermissionDiffDeniedError when actor lacks maintainer role", () => {
    const proposedPolicy: RolePolicy = { version: 2, roles: basePolicy.roles };

    expect(() =>
      computePermissionDiff({
        actorRoles: ["user"],
        currentPolicy: basePolicy,
        proposedPolicy,
      })
    ).toThrow(PermissionDiffDeniedError);
  });

  it("throws StalePolicyInputError when proposed policy version is stale", () => {
    const staleProposedPolicy: RolePolicy = {
      version: 1, // Same as current version (1)
      roles: basePolicy.roles,
    };

    expect(() =>
      computePermissionDiff({
        actorRoles: ["maintainer"],
        currentPolicy: basePolicy,
        proposedPolicy: staleProposedPolicy,
      })
    ).toThrow(StalePolicyInputError);
  });
});
