"""Account-level audit-logging state reader (defense-evasion enrichment).

When CloudTrail is not logging OR GuardDuty has no enabled detector, an attacker operates unseen
in the account.  This reader surfaces that condition so the ranking model can lift every attack
path's probability for the affected tenant (see path_priors._LOGGING_DISABLED_LIFT).

Plain boto3 reader: inject ``cloudtrail`` and ``guardduty`` clients so this runs against real
AWS or in-process moto (get_trail_status/IsLogging and list_detectors are both supported).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AccountLoggingState:
    """Resolved audit-logging posture for one AWS account."""

    cloudtrail_logging: bool  # True iff at least one trail has IsLogging=True
    guardduty_enabled: bool  # True iff at least one detector is in ENABLED state

    @property
    def logging_disabled(self) -> bool:
        """True when EITHER CloudTrail is not logging OR GuardDuty is not enabled.

        An attacker in such an account can operate unseen — either detection surface is absent.
        Used by path_priors.leaf_probability to lift every attack path's probability.
        """
        return not (self.cloudtrail_logging and self.guardduty_enabled)


def read_account_logging_state(cloudtrail: object, guardduty: object) -> AccountLoggingState:
    """Read CloudTrail + GuardDuty logging posture from one AWS account.

    Args:
        cloudtrail: boto3 CloudTrail client (or moto equivalent).
        guardduty: boto3 GuardDuty client (or moto equivalent).

    Returns:
        :class:`AccountLoggingState` with resolved ``cloudtrail_logging`` and
        ``guardduty_enabled`` flags.
    """
    # -- CloudTrail: any trail with IsLogging=True counts as active --
    cloudtrail_logging = False
    try:
        trails = cloudtrail.describe_trails().get("trailList", [])  # type: ignore[attr-defined]
        for trail in trails:
            trail_arn = trail.get("TrailARN") or trail.get("Name", "")
            if not trail_arn:
                continue
            try:
                status = cloudtrail.get_trail_status(Name=trail_arn)  # type: ignore[attr-defined]
                if status.get("IsLogging", False):
                    cloudtrail_logging = True
                    break
            except Exception:  # noqa: S112 — skip unreadable trail, never abort
                continue
    except Exception:  # noqa: S110 — if describe_trails fails, assume not logging
        pass

    # -- GuardDuty: any detector in ENABLED state counts as active --
    guardduty_enabled = False
    try:
        detector_ids = guardduty.list_detectors().get("DetectorIds", [])  # type: ignore[attr-defined]
        for det_id in detector_ids:
            try:
                det = guardduty.get_detector(DetectorId=det_id)  # type: ignore[attr-defined]
                if det.get("Status", "") == "ENABLED":
                    guardduty_enabled = True
                    break
            except Exception:  # noqa: S112 — skip unreadable detector, never abort
                continue
    except Exception:  # noqa: S110 — if list_detectors fails, assume not enabled
        pass

    return AccountLoggingState(
        cloudtrail_logging=cloudtrail_logging,
        guardduty_enabled=guardduty_enabled,
    )


__all__ = ["AccountLoggingState", "read_account_logging_state"]
