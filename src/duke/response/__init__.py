"""Safe, dry-run-only incident response planning.

Response planning in Duke never executes an action against a real
system. It consumes telemetry and an investigation result, correlates
the finding into a deterministic preliminary ``Incident``, and proposes
``ResponseAction`` records that a human could take — every one flagged
``dry_run=True``, ``requires_approval=True``, and ``status=PLANNED``.
"""

from duke.response.plan import (
    ResponseActionGroup,
    ResponseCategory,
    ResponsePlan,
)
from duke.response.t1078 import plan_t1078_response
from duke.response.t1110 import plan_t1110_response

__all__ = [
    "ResponseActionGroup",
    "ResponseCategory",
    "ResponsePlan",
    "plan_t1078_response",
    "plan_t1110_response",
]
