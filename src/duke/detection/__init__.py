"""Behaviour-based detection of adversary activity from normalized telemetry."""

from duke.detection.events import EventLoadError, load_events
from duke.detection.t1078 import detect_t1078

__all__ = ["EventLoadError", "detect_t1078", "load_events"]
