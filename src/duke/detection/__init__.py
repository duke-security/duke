"""Behaviour-based detection of adversary activity from normalized telemetry."""

from duke.detection.t1078 import detect_t1078
from duke.telemetry import EventLoadError, load_events

# ``load_events`` and ``EventLoadError`` are re-exported here for
# compatibility: artefact ingestion lives in ``duke.telemetry``, but
# ``duke detect`` historically exposed these from the detection package.
__all__ = ["EventLoadError", "detect_t1078", "load_events"]
