"""Pure ownership-aware transaction planning models for future FFTIC setup."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class OperationKind(str, Enum):
    CREATE_PRIVATE_GENERATION = "create private generation"
    PUBLISH_GENERATION = "publish generation atomically"
    COPY_OWNED_FILE = "copy exact owned bootstrap file"
    VERIFY_ABSENCE = "verify expected absence"
    VERIFY_PRIOR_HASH = "verify expected prior hash"
    BACK_UP_TARGET = "back up existing owned target"
    INSTALL_PREREQUISITE = "install a missing prerequisite"
    WRITE_CONFIGURATION = "write generated configuration"
    REMOVE_OWNED_FILE = "remove an exact-owned file"
    RETAIN_SHARED_PREREQUISITE = "retain shared prerequisite"
    RESTORE_PREVIOUS = "restore a previous owned version"
    STOP_DRIFT = "stop on drift"
    STOP_UNOWNED_COLLISION = "stop on unowned collision"


class ExpectedTargetState(str, Enum):
    ABSENT = "absent"
    EXACT_HASH = "exact hash"
    OWNED_EXACT_HASH = "owned exact hash"
    SHARED_RETAINED = "shared prerequisite retained"


@dataclass(frozen=True)
class PlannedOperation:
    kind: OperationKind
    source: Path | None
    destination: Path | None
    expected_source_hash: str | None
    expected_target_state: ExpectedTargetState
    expected_target_hash: str | None
    ownership_identity: str
    backup_path: Path | None
    recovery_information: str
    rollback_action: str
    reason: str


@dataclass(frozen=True)
class TargetObservation:
    exists: bool
    sha256: str | None = None
    ownership_identity: str | None = None
    backup_path: Path | None = None


@dataclass(frozen=True)
class TransactionPlan:
    transaction_id: str
    operations: tuple[PlannedOperation, ...]

    @property
    def can_execute(self) -> bool:
        return not any(op.kind in {
            OperationKind.STOP_DRIFT,
            OperationKind.STOP_UNOWNED_COLLISION,
        } for op in self.operations)


def plan_owned_file_install(
    *,
    transaction_id: str,
    source: Path,
    destination: Path,
    expected_source_hash: str,
    ownership_identity: str,
    observed: TargetObservation,
    prior_owned_hash: str | None = None,
) -> TransactionPlan:
    """Plan one exact file placement, stopping on collisions or receipt drift."""
    common = dict(
        source=Path(source), destination=Path(destination),
        expected_source_hash=expected_source_hash,
        ownership_identity=ownership_identity,
        backup_path=observed.backup_path,
    )
    if not observed.exists:
        ops = (
            PlannedOperation(
                OperationKind.VERIFY_ABSENCE,
                expected_target_state=ExpectedTargetState.ABSENT,
                expected_target_hash=None,
                recovery_information="No prior target exists.",
                rollback_action="No change if verification fails.",
                reason="Refuse a race or newly introduced collision before copying.",
                **common,
            ),
            PlannedOperation(
                OperationKind.COPY_OWNED_FILE,
                expected_target_state=ExpectedTargetState.ABSENT,
                expected_target_hash=None,
                recovery_information="Remove only while the destination still has the written hash.",
                rollback_action="Remove the exact transaction-owned destination.",
                reason="Install the reviewed bootstrap byte-for-byte.",
                **common,
            ),
        )
        return TransactionPlan(transaction_id, ops)
    if observed.ownership_identity != ownership_identity:
        return TransactionPlan(transaction_id, (PlannedOperation(
            OperationKind.STOP_UNOWNED_COLLISION,
            expected_target_state=ExpectedTargetState.ABSENT,
            expected_target_hash=None,
            recovery_information="Leave the existing target untouched.",
            rollback_action="None; no mutation is authorized.",
            reason="The destination exists without this integration's ownership receipt.",
            **common,
        ),))
    if prior_owned_hash is None or observed.sha256 != prior_owned_hash:
        return TransactionPlan(transaction_id, (PlannedOperation(
            OperationKind.STOP_DRIFT,
            expected_target_state=ExpectedTargetState.OWNED_EXACT_HASH,
            expected_target_hash=prior_owned_hash,
            recovery_information="Preserve the drifted target and its receipt for review.",
            rollback_action="None; do not overwrite or delete drifted state.",
            reason="The owned target no longer matches its recorded prior hash.",
            **common,
        ),))
    backup = observed.backup_path or destination.with_name(destination.name + ".amethyst-backup")
    common["backup_path"] = backup
    return TransactionPlan(transaction_id, (
        PlannedOperation(
            OperationKind.VERIFY_PRIOR_HASH,
            expected_target_state=ExpectedTargetState.OWNED_EXACT_HASH,
            expected_target_hash=prior_owned_hash,
            recovery_information=f"Verified prior bytes can be recovered from {backup}.",
            rollback_action="No change if verification fails.",
            reason="Prevent an update from overwriting changed owned state.",
            **common,
        ),
        PlannedOperation(
            OperationKind.BACK_UP_TARGET,
            expected_target_state=ExpectedTargetState.OWNED_EXACT_HASH,
            expected_target_hash=prior_owned_hash,
            recovery_information=f"Keep the exact previous version at {backup}.",
            rollback_action="Restore the backup only if the new target still matches its receipt.",
            reason="Make the side-by-side managed update recoverable.",
            **common,
        ),
        PlannedOperation(
            OperationKind.COPY_OWNED_FILE,
            expected_target_state=ExpectedTargetState.OWNED_EXACT_HASH,
            expected_target_hash=prior_owned_hash,
            recovery_information=f"Previous bytes remain at {backup}.",
            rollback_action=f"Restore {backup} after verifying the newly written hash.",
            reason="Replace an exact prior owned version with reviewed bytes.",
            **common,
        ),
    ))


def plan_shared_prerequisite_retention(
    *, transaction_id: str, destination: Path, ownership_identity: str,
) -> TransactionPlan:
    return TransactionPlan(transaction_id, (PlannedOperation(
        OperationKind.RETAIN_SHARED_PREREQUISITE,
        source=None, destination=Path(destination), expected_source_hash=None,
        expected_target_state=ExpectedTargetState.SHARED_RETAINED,
        expected_target_hash=None, ownership_identity=ownership_identity,
        backup_path=None,
        recovery_information="The shared prefix prerequisite remains installed.",
        rollback_action="Do not uninstall a shared prerequisite during removal.",
        reason="Removing a shared runtime could break other prefix consumers.",
    ),))
