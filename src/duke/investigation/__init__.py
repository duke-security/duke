"""Evidence-led security investigation workflows."""

from duke.investigation.result import InvestigationResult, TimelineEntry
from duke.investigation.t1078 import investigate_t1078
from duke.investigation.t1110 import investigate_t1110

__all__ = [
    "InvestigationResult",
    "TimelineEntry",
    "investigate_t1078",
    "investigate_t1110",
]
