"""
Live mode - the "real-time" part of Task 5.0.

Replays a recorded file of connection records as if the connections were arriving now,
at a chosen speed (10, 100 or 1,000 per second), and checks them in micro-batches:
each time the dashboard asks (about once a second), every connection that has
"arrived" since the last time is checked together. Real network sensors work the same
way, because checking connections together is hundreds of times faster than one by
one (measured: 1 connection ~48 ms, 1,000 connections ~270 ms).

This is a REPLAY of recorded traffic, not a capture of this computer's own network:
working out the measurements from live packets needs extra tools (for the CIC-IDS2017
format, the CICFlowMeter tool). Files in either format can be replayed; each is checked
by the sensor trained on that dataset.

Replays are kept in this server's memory, so they assume one server process (the
normal way this app is started). A replay nobody has asked about for 10 minutes is
dropped without an end entry in the audit log.
"""
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

import pandas as pd

from network_sensor.actions import PRIORITIES, where_of
from network_sensor.errors import ScanError
from network_sensor.evaluate import compute_metrics
from network_sensor.features import InputError, prepare_features
from network_sensor.spec import dataset_of_columns, get_spec

SPEEDS = (10, 100, 1000)          # connections per second a user can choose
MAX_BATCH = 2000                  # most connections checked in one step
MAX_ALERTS_PER_STEP = 200         # alerts sent back per step (the totals count all of them)
MAX_SESSIONS = 3                  # live replays running at the same time on the whole server
IDLE_SECONDS = 600                # a replay nobody has asked about for this long is dropped


@dataclass
class LiveSession:
    id: str
    user_id: str
    connections: pd.DataFrame
    speed: int
    started_at: float
    last_seen: float
    details: dict                                   # file name, size, fingerprint (for the audit log)
    dataset: str = "nsl_kdd"                        # which format the file is in
    position: int = 0                               # connections checked so far
    alerts: int = 0
    possible_new_attacks: int = 0
    by_priority: Dict[str, int] = field(default_factory=lambda: {p: 0 for p in PRIORITIES})
    batches: int = 0
    total_check_ms: float = 0.0
    slowest_check_ms: float = 0.0
    verdicts: List[int] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def has_labels(self) -> bool:
        return "label" in self.connections.columns

    @property
    def dataset_title(self) -> str:
        return get_spec(self.dataset).title


class LiveSessions:
    """All live replays on this server. `clock` is replaceable so tests can fake time."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._sessions: Dict[str, LiveSession] = {}
        self._lock = threading.Lock()

    def start(self, user_id: str, connections: pd.DataFrame, speed: int,
              details: dict) -> Tuple[LiveSession, Optional[dict]]:
        """Start a replay. Each user has at most one: starting a new one ends the old
        one, whose summary is returned so it can be written to the audit log."""
        if speed not in SPEEDS:
            raise ScanError(400, "Speed must be " + ", ".join(f"{s:,}" for s in SPEEDS)
                            + " connections per second.")
        dataset = dataset_of_columns(connections.columns)
        try:
            prepare_features(connections, get_spec(dataset))   # refuse bad values now, not halfway through
        except InputError as e:
            raise ScanError(400, str(e))
        with self._lock:
            self._drop_idle()
            others = [s for s in self._sessions.values() if s.user_id != user_id]
            if len(others) >= MAX_SESSIONS:
                raise ScanError(429, "Too many live replays are running. Please try again later.")
            replaced = None
            for old in [s for s in self._sessions.values() if s.user_id == user_id]:
                replaced = self._summary(self._sessions.pop(old.id), "replaced by a new live replay")
            now = self._clock()
            session = LiveSession(id=secrets.token_urlsafe(12), user_id=user_id,
                                  connections=connections.reset_index(drop=True), speed=speed,
                                  started_at=now, last_seen=now, details=details, dataset=dataset)
            self._sessions[session.id] = session
        return session, replaced

    def step(self, session_id: str, user_id: str, model) -> dict:
        """Check every connection that has 'arrived' since the last step. When the file
        is finished, the replay ends and the answer includes its 'summary'.

        `model` is the trained sensor, or a function that returns the trained sensor
        for a dataset name (e.g. SensorService.model), so each replay gets the sensor
        that matches its file's format."""
        session = self._owned(session_id, user_id)
        if callable(model):
            model = model(session.dataset)
        with session.lock:                          # two steps of one replay never overlap
            now = self._clock()
            session.last_seen = now
            total = len(session.connections)
            arrived = min(total, int((now - session.started_at) * session.speed))
            end = min(arrived, session.position + MAX_BATCH)
            first_row = session.position
            batch = session.connections.iloc[first_row:end]

            new_alerts, check_ms = [], 0.0
            if len(batch):
                started = time.perf_counter()
                explanations = model.explain(batch)
                check_ms = (time.perf_counter() - started) * 1000
                session.batches += 1
                session.total_check_ms += check_ms
                session.slowest_check_ms = max(session.slowest_check_ms, check_ms)
                for i, e in enumerate(explanations):
                    session.verdicts.append(1 if e["verdict"] == "attack" else 0)
                    if e["verdict"] != "attack":
                        continue
                    alert = {"row": first_row + i + 1, **e}
                    where = where_of(batch, i)
                    if where:
                        alert["where"] = where
                    if e.get("priority") in session.by_priority:
                        session.by_priority[e["priority"]] += 1
                    if session.has_labels:
                        alert["label_in_file"] = batch["label"].iat[i]
                    new_alerts.append(alert)
                session.alerts += len(new_alerts)
                session.possible_new_attacks += sum(1 for a in new_alerts if a["votes"]["random_forest"] == 0)
                session.position = end

            result = {
                "session_id": session.id,
                "speed": session.speed,
                "total": total,
                "checked": session.position,
                "done": session.position >= total,
                "batch_size": len(batch),
                "check_ms": round(check_ms, 1),
                "behind_by": arrived - session.position,    # arrived but not checked yet (over MAX_BATCH)
                "alerts_in_step": len(new_alerts),
                "alerts": new_alerts[:MAX_ALERTS_PER_STEP],
                "totals": self._totals(session),
            }
        if result["done"]:
            with self._lock:
                self._sessions.pop(session.id, None)
            result["summary"] = self._summary(session, "completed")
        return result

    def stop(self, session_id: str, user_id: str) -> dict:
        session = self._owned(session_id, user_id)
        with self._lock:
            self._sessions.pop(session.id, None)
        return self._summary(session, "stopped by the user")

    # ------------------------------------------------------------------ helpers
    def _owned(self, session_id: str, user_id: str) -> LiveSession:
        """The replay, if it exists and belongs to this user (others' look 'not found')."""
        with self._lock:
            self._drop_idle()
            session = self._sessions.get(session_id)
        if session is None or session.user_id != user_id:
            raise ScanError(404, "This live replay was not found. It may have finished, been stopped, "
                                 f"or been idle for more than {IDLE_SECONDS // 60} minutes.")
        return session

    def _drop_idle(self) -> None:          # call with self._lock held
        now = self._clock()
        for sid in [sid for sid, s in self._sessions.items() if now - s.last_seen > IDLE_SECONDS]:
            del self._sessions[sid]

    @staticmethod
    def _totals(session: LiveSession) -> dict:
        totals = {
            "alerts": session.alerts,
            "possible_new_attacks": session.possible_new_attacks,
            "by_priority": [{"name": p, "alerts": n} for p, n in session.by_priority.items()],
            "average_check_ms": round(session.total_check_ms / session.batches, 1) if session.batches else 0.0,
            "slowest_check_ms": round(session.slowest_check_ms, 1),
        }
        if session.has_labels and session.verdicts:
            normal = get_spec(session.dataset).normal_label
            truth = (session.connections["label"].iloc[:len(session.verdicts)] != normal).astype(int)
            m = compute_metrics(truth, session.verdicts)
            totals["label_check"] = {k: m[k] for k in ("precision", "recall", "false_positives", "true_positives")}
        return totals

    def _summary(self, session: LiveSession, outcome: str) -> dict:
        totals = self._totals(session)
        summary = {
            "session_id": session.id,
            "outcome": outcome,
            "speed": session.speed,
            "connections_checked": session.position,
            "connections_in_file": len(session.connections),
            "dataset": session.dataset,
            "alerts": totals["alerts"],
            "possible_new_attacks": totals["possible_new_attacks"],
            "alerts_by_priority": dict(session.by_priority),
            "batches": session.batches,
            "average_check_ms": totals["average_check_ms"],
            "slowest_check_ms": totals["slowest_check_ms"],
            **session.details,
        }
        if "label_check" in totals:
            summary["precision_against_labels"] = totals["label_check"]["precision"]
        return summary
