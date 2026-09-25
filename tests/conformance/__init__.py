"""Reusable, test-only scenario-conformance infrastructure.

Everything under this package lives under ``tests/``: the typed
:class:`ScenarioConformanceFixture`, the reusable check functions, and the
independent probe scenario. None of it is shipped as a Duke runtime module,
nothing here may import from any ``duke.*.t1078`` implementation module, and
no probe or fixture ever enters ``duke.scenarios.builtins``.
"""
