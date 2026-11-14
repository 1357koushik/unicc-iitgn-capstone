"""Evaluation harness for the retrieval engine (work package B4, docs/RETRIEVAL_V2_PLAN.md).

Modules that run on the server (``schema``, ``sealed``, ``registry``, ``adapters``, ``runner``) use only the
standard library and PyYAML. Scoring (``metrics``, ``calibration``, ``stats``, ``scoring``, ``report``,
``gates``) needs NumPy and runs on the PC.

Definitions of every number are in ``benchmarks_v2/eval/METHODS.md``.
"""

HARNESS_VERSION = "b4-1"
