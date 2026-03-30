
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
    def __init__(self, window_seconds=3600):
        self.window_seconds=window_seconds; self._events=deque()
        self._lock=threading.Lock(); self._counts=defaultdict(int)
        self._total=0; self._params=defaultdict(list)
    def record(self, event):
        with self._lock:
            self._prune(); self._events.append(event)
            self._counts[event.tool_name]+=1; self._total+=1
            self._params[event.tool_name].append(set(event.params_keys))
    def evaluate(self, tool_name, params_keys):
        with self._lock:
            self._prune(); reasons=[]; scores=[]
            if tool_name not in self._counts:
                reasons.append(f"Tool never seen"); scores.append(1.0)
            else:
                fs=self._freq_score(tool_name)
                if fs>0.5: reasons.append(f"Call rate anomaly")
                scores.append(fs)
                ps=self._param_score(tool_name,set(params_keys))
                if ps>0.5: reasons.append(f"Param structure deviation")
                scores.append(ps)
            score=max(scores) if scores else 0.0
            return AnomalySignal(is_anomalous=score>=0.6,score=round(score,3),reasons=reasons,agent_subject="",tool_name=tool_name)
    def is_warm(self): return self._total>=50
    def _prune(self):
        cutoff=time.time()-self.window_seconds
        while self._events and self._events[0].timestamp<cutoff:
            old=self._events.popleft(); self._counts[old.tool_name]-=1
            if self._counts[old.tool_name]<=0: del self._counts[old.tool_name]
            self._total-=1
    def _freq_score(self, tool_name):
        if self._total<10: return 0.0
        expected=self._counts.get(tool_name,0)/max(self._total,1)
        cutoff=time.time()-60
        recent=sum(1 for e in self._events if e.timestamp>=cutoff and e.tool_name==tool_name)
        total_r=sum(1 for e in self._events if e.timestamp>=cutoff)
        current=recent/max(total_r,1)
        if expected==0: return 0.0
        return min(1.0/(1.0+math.exp(-2.0*(current/expected-3.0))),1.0)
    def _param_score(self, tool_name, current):
        hist=self._params.get(tool_name,[])
        if not hist: return 0.0
        common=Counter(frozenset(s) for s in hist).most_common(1)[0][0]
        union=common|current
        if not union: return 0.0
        return 1.0-len(common&current)/len(union)
class AnomalyDetector:
    def __init__(self, window_seconds=3600, block_threshold=0.9, alert_threshold=0.6, observe_only_during_warmup=True):
        self.window_seconds=window_seconds; self.block_threshold=block_threshold
        self.alert_threshold=alert_threshold; self.observe_only_during_warmup=observe_only_during_warmup
        self._baselines={}; self._lock=threading.Lock()
    def observe_and_evaluate(self, agent_subject, tool_name, params):
        b=self._get(agent_subject)
        b.record(CallEvent(agent_subject=agent_subject,tool_name=tool_name,params_keys=sorted(params.keys())))
        s=b.evaluate(tool_name,sorted(params.keys())); s.agent_subject=agent_subject
        if self.observe_only_during_warmup and not b.is_warm():
            if s.score>=self.block_threshold:
                s.score=min(s.score,self.alert_threshold-0.01); s.is_anomalous=s.score>=self.alert_threshold
        return s
    def reset_baseline(self, agent_subject):
        with self._lock: self._baselines.pop(agent_subject,None)
    def _get(self, agent_subject):
        with self._lock:
            if agent_subject not in self._baselines:
                self._baselines[agent_subject]=AgentBaseline(self.window_seconds)
            return self._baselines[agent_subject]
