/**
 * Permission Diff Preview for Role and Policy Changes (#863).
 *
 * Provides before/after permission diff computation, impact analysis on affected
 * actors and actions, and explicit confirmation requirements for broad changes.
 */

import { type Role, type Permission, isRole } from "./rbac";

export interface RolePolicy {
  version: number;
  roles: Record<Role | string, Permission[]>;
}

export interface PermissionDiffItem {
  role: string;
  addedPermissions: Permission[];
  removedPermissions: Permission[];
  unchangedPermissions: Permission[];
  affectedActions: string[];
}

export interface PermissionDiffPreview {
  currentVersion: number;
  proposedVersion: number;
  diffs: PermissionDiffItem[];
  isNoOp: boolean;
  isBroadChange: boolean;
  requiresConfirmation: boolean;
  confirmationReason?: string;
  summary: {
    totalAdded: number;
    totalRemoved: number;
    rolesModified: string[];
  };
}

export class PermissionDiffDeniedError extends Error {
  constructor(message: string = "Actor is not authorized to preview or apply policy diffs.") {
    super(message);
    this.name = "PermissionDiffDeniedError";
  }
}

export class StalePolicyInputError extends Error {
  constructor(currentVersion: number, providedVersion: number) {
    super(
      `Stale policy input: current active policy version is ${currentVersion}, but provided base version is ${providedVersion}.`
    );
    this.name = "StalePolicyInputError";
  }
}

/** Critical permissions that trigger broad change confirmation when added to non-service/user roles. */
export const CRITICAL_PERMISSIONS: Permission[] = [
  "admin.audit.write",
  "admin.audit.export",
  "admin.export.any",
  "admin.recovery.write",
  "admin.impersonation.write",
  "admin.limits.write",
  "internal.reconciliation.execute",
];

/**
 * Maps permissions to user-visible actions for impact assessment.
 */
export function getAffectedActions(permission: string): string[] {
  switch (permission) {
    case "own.data.read":
      return ["Read user profile and private data"];
    case "own.data.export":
      return ["Export personal records payload"];
    case "own.data.import":
      return ["Import saved pool watchlists"];
    case "own.receipts.read":
      return ["View personal transaction receipts"];
    case "admin.audit.read":
      return ["View protocol parameters audit trail"];
    case "admin.audit.write":
      return ["Modify protocol parameters and records"];
    case "admin.audit.export":
      return ["Export protocol audit logs"];
    case "admin.export.any":
      return ["Export any user's private data payload"];
    case "admin.recovery.read":
      return ["View pending-action recovery state"];
    case "admin.recovery.write":
      return ["Execute manual action recovery & overrides"];
    case "admin.impersonation.read":
      return ["View active impersonation sessions"];
    case "admin.impersonation.write":
      return ["Initiate maintainer impersonation session"];
    default:
      return [`Perform action guarded by '${permission}'`];
  }
}

export interface ComputePermissionDiffOptions {
  actorRoles: string[];
  currentPolicy: RolePolicy;
  proposedPolicy: RolePolicy;
}

/**
 * Compute the permission diff preview between current and proposed role policies.
 *
 * @throws {PermissionDiffDeniedError} if actor lacks maintainer role
 * @throws {StalePolicyInputError} if proposed policy is based on an outdated version
 */
export function computePermissionDiff(
  options: ComputePermissionDiffOptions
): PermissionDiffPreview {
  const { actorRoles, currentPolicy, proposedPolicy } = options;

  // Authorization check: Actor must have maintainer role
  if (!actorRoles.includes("maintainer")) {
    throw new PermissionDiffDeniedError();
  }

  // Stale policy input check
  if (proposedPolicy.version <= currentPolicy.version) {
    throw new StalePolicyInputError(currentPolicy.version, proposedPolicy.version);
  }

  const allRoles = Array.from(
    new Set([...Object.keys(currentPolicy.roles), ...Object.keys(proposedPolicy.roles)])
  );

  const diffs: PermissionDiffItem[] = [];
  let totalAdded = 0;
  let totalRemoved = 0;
  const rolesModified: string[] = [];
  let hasBroadChange = false;
  const confirmationReasons: string[] = [];

  for (const role of allRoles) {
    const currentPerms = new Set(currentPolicy.roles[role] || []);
    const proposedPerms = new Set(proposedPolicy.roles[role] || []);

    const added = Array.from(proposedPerms).filter((p) => !currentPerms.has(p as Permission)) as Permission[];
    const removed = Array.from(currentPerms).filter((p) => !proposedPerms.has(p as Permission)) as Permission[];
    const unchanged = Array.from(currentPerms).filter((p) => proposedPerms.has(p as Permission)) as Permission[];

    if (added.length > 0 || removed.length > 0) {
      rolesModified.push(role);
      totalAdded += added.length;
      totalRemoved += removed.length;

      const affectedActions = Array.from(
        new Set([...added.flatMap(getAffectedActions), ...removed.flatMap(getAffectedActions)])
      );

      diffs.push({
        role,
        addedPermissions: added,
        removedPermissions: removed,
        unchangedPermissions: unchanged,
        affectedActions,
      });

      // Broad change check 1: Adding critical permissions to 'user' or non-admin roles
      const addedCritical = added.filter((p) => CRITICAL_PERMISSIONS.includes(p));
      if (addedCritical.length > 0 && role === "user") {
        hasBroadChange = true;
        confirmationReasons.push(
          `Granting critical administrative permission(s) [${addedCritical.join(", ")}] to '${role}' role.`
        );
      }

      // Broad change check 2: Removing core permissions from user
      if (role === "user" && removed.includes("own.data.read")) {
        hasBroadChange = true;
        confirmationReasons.push("Revoking core data access permission 'own.data.read' from user role.");
      }

      // Broad change check 3: High volume change (> 3 changes on a single role)
      if (added.length + removed.length > 3) {
        hasBroadChange = true;
        confirmationReasons.push(`High volume policy modification (${added.length + removed.length} changes) on role '${role}'.`);
      }
    } else {
      diffs.push({
        role,
        addedPermissions: [],
        removedPermissions: [],
        unchangedPermissions: unchanged,
        affectedActions: [],
      });
    }
  }

  const isNoOp = totalAdded === 0 && totalRemoved === 0;

  return {
    currentVersion: currentPolicy.version,
    proposedVersion: proposedPolicy.version,
    diffs,
    isNoOp,
    isBroadChange: hasBroadChange,
    requiresConfirmation: hasBroadChange,
    confirmationReason: confirmationReasons.length > 0 ? confirmationReasons.join(" ") : undefined,
    summary: {
      totalAdded,
      totalRemoved,
      rolesModified,
    },
  };
}
