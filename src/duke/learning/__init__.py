"""Guided learning paths and introductory Python lessons for Duke.

The learning package is metadata only: it models guided learning content and
renders it deterministically. It never executes a command, never writes or
modifies a learner's files, never grades work, and never persists progress.
"""

from duke.learning.models import (
    Exercise,
    Hint,
    KnowledgeCheck,
    LearningObjective,
    LearningPath,
    LearningStep,
)
from duke.learning.render import render_path, render_step
from duke.learning.t1078 import T1078_LEARNING_PATH, t1078_learning_path
from duke.learning.t1110 import T1110_LEARNING_PATH, t1110_learning_path

__all__ = [
    "Exercise",
    "Hint",
    "KnowledgeCheck",
    "LearningObjective",
    "LearningPath",
    "LearningStep",
    "T1078_LEARNING_PATH",
    "T1110_LEARNING_PATH",
    "render_path",
    "render_step",
    "t1078_learning_path",
    "t1110_learning_path",
]
