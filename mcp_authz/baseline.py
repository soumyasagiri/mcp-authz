from __future__ import annotations
import math, time, threading, logging
from collections import defaultdict, deque, Counter
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CallEvent:
    agent_subject: str
    tool_name: str
    params_keys: list
    timestamp: float = field(default_factory=time.time)


@dataclass
class AnomalySignal:
    is_anomalous: bool
    score: float
    reasons: list
    agent_subject: str
    tool_name: str

    @property
    def should_block(self): return self.score >= 0.9

    @property
    def should_alert(self): return self.score >= 0.6


class AgentBaseline:
    def __init__(self, window_seconds=3600, decay_factor=0.001):
        self.window_seconds = window_seconds
        self.decay_factor = decay_factor
        self._events = deque()
        self._lock = threading.Lock()
        self._tool_weights: dict[str, float] = defaultdict(float)
        self._total_weight: float = 0.0
        self._param_keys: dict[str, list] = defaultdict(list)

    def record(self, event: CallEvent):
        with self._lock:
            self._prune()
            self._events.append(event)
            age = 0.0
            w = math.exp(-self.decay_factor * age)
            self._tool_weights[event.tool_name] += w
            self._total_weight += w
            self._param_keys[event.tool_name].append(set(event.params_keys))

    def evaluate(self, tool_name: str, params_keys: list) -> AnomalySignal:
        with self._lock:
            self._prune()
            reasons, scores = [], []

            if tool_name not in self._tool_weights or self._tool_weights[tool_name] == 0:
                reasons.append(f"Tool '{tool_name}' never seen before for this agent")
                scores.append(1.0)
            else:
                fs = self._freq_score(tool_name)
                if fs > 0.5:
                    reasons.append(f"Call rate anomaly for '{tool_name}' (score:{fs:.2f})")
                scores.append(fs)

                ps = self._param_score(tool_name, set(params_keys))
                if ps > 0.5:
                    reasons.append(f"Parameter structure deviation for '{tool_name}'")
                scores.append(ps)

            score = max(scores) if scores else 0.0
            return AnomalySignal(
                is_anomalous=score >= 0.6,
                score=round(score, 3),
                reasons=reasons,
                agent_subject="",
                tool_name=tool_name,
            )

    def is_warm(self) -> bool:
        with self._lock:
            return self._total_weight >= 10.0

    def _prune(self):
        cutoff = time.time() - self.window_seconds
        while self._events and self._events[0].timestamp < cutoff:
            old = self._events.popleft()
            age = time.time() - old.timestamp
            w = math.exp(-self.decay_factor * age)
            self._tool_weights[old.tool_name] = max(
                0.0, self._tool_weights[old.tool_name] - w
            )
            self._total_weight = max(0.0, self._total_weight - w)

    def _freq_score(self, tool_name: str) -> float:
        if self._total_weight < 1.0:
            return 0.0
        expected_ratio = self._tool_weights.get(tool_name, 0) / max(self._total_weight, 1)
        cutoff = time.time() - 60
        recent_tool = sum(
            math.exp(-self.decay_factor * (time.time() - e.timestamp))
            for e in self._events if e.timestamp >= cutoff and e.tool_name == tool_name
        )
        recent_total = sum(
            math.exp(-self.decay_factor * (time.time() - e.timestamp))
            for e in self._events if e.timestamp >= cutoff
        )
        current_ratio = recent_tool / max(recent_total, 0.001)
        if expected_ratio == 0:
            return 0.0
        ratio = current_ratio / expected_ratio
        return min(1.0 / (1.0 + math.exp(-2.0 * (ratio - 3.0))), 1.0)

    def _param_score(self, tool_name: str, current: set) -> float:
        hist = self._param_keys.get(tool_name, [])
        if not hist:
            return 0.0
        common = Counter(frozenset(s) for s in hist).most_common(1)[0][0]
        union = common | current
        if not union:
            return 0.0
        return 1.0 - len(common & current) / len(union)


class AnomalyDetector:
    def __init__(self, window_seconds=3600, block_threshold=0.9,
                 alert_threshold=0.6, observe_only_during_warmup=True,
                 decay_factor=0.001):
        self.window_seconds = window_seconds
        self.block_threshold = block_threshold
        self.alert_threshold = alert_threshold
        self.observe_only_during_warmup = observe_only_during_warmup
        self.decay_factor = decay_factor
        self._baselines: dict[str, AgentBaseline] = {}
        self._lock = threading.Lock()

    def observe_and_evaluate(self, agent_subject, tool_name, params) -> AnomalySignal:
        baseline = self._get(agent_subject)
        event = CallEvent(
            agent_subject=agent_subject,
            tool_name=tool_name,
            params_keys=sorted(params.keys()),
        )
        baseline.record(event)
        sig = baseline.evaluate(tool_name, sorted(params.keys()))
        sig.agent_subject = agent_subject

        if self.observe_only_during_warmup and not baseline.is_warm():
            if sig.score >= self.block_threshold:
                sig.score = min(sig.score, self.alert_threshold - 0.01)
                sig.is_anomalous = sig.score >= self.alert_threshold
        return sig

    def reset_baseline(self, agent_subject: str):
        with self._lock:
            self._baselines.pop(agent_subject, None)

    def _get(self, agent_subject: str) -> AgentBaseline:
        with self._lock:
            if agent_subject not in self._baselines:
                self._baselines[agent_subject] = AgentBaseline(
                    window_seconds=self.window_seconds,
                    decay_factor=self.decay_factor,
                )
            return self._baselines[agent_subject]
