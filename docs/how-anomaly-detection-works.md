# How behavioral anomaly detection works

## Why policy alone is not enough

Policy enforces rules. Rules cover the cases you anticipated. Anomaly detection covers the cases you did not.

An agent that has been compromised, confused by a prompt injection, or whose credentials have been stolen still has a valid token. It still passes the delegation chain check. It still passes the policy check on each individual call. What changes is the pattern of calls it makes.

A stolen credential used to enumerate customer accounts makes calls that look individually legitimate. A prompt injection that causes an agent to extract data it normally would not touch passes all the rule checks. What gives it away is the deviation from the agent's own normal behavior.

That is what the anomaly detector measures.

---

## The baseline

When an agent makes its first call through mcp-authz, the anomaly detector starts building a behavioral baseline for that agent. The baseline tracks two things:

1. How often the agent calls each tool relative to its total call volume
2. What parameter structure the agent typically uses when calling each tool

The baseline is per-agent, not global. A batch processing agent that calls `account_balance` a thousand times per hour is not anomalous. An interactive assistant that normally calls it twice per session and suddenly calls it a thousand times is anomalous.

---

## Why time-weighting matters

The naive approach is to count calls over a sliding window. The problem is the warmup bypass attack: an adversary who knows you are building a baseline makes legitimate calls first to establish a "good" pattern, then pivots to malicious behavior. The malicious calls look normal relative to the accumulated count.

mcp-authz uses Exponentially Weighted Moving Average (EWMA) instead of a raw count. The formula is:

```
weighted_score = alpha * recent_observation + (1 - alpha) * historical_average
```

With a decay factor applied to age, recent calls count more than old calls. A baseline built two hours ago carries less weight than calls from the last five minutes. An attacker who spent twenty minutes making legitimate calls cannot coast on that history indefinitely. The baseline continuously updates toward current behavior.

This is the same technique used in network intrusion detection systems and financial fraud detection.

Academic reference: Hunter, J.S. (1986). The Exponentially Weighted Moving Average. Journal of Quality Technology.

---

## Two detection signals

**Frequency anomaly (Z-score)**

Compares the current call rate for a specific tool against the agent's historical rate for that tool.

If the agent historically calls `account_balance` 5% of the time and suddenly `account_search` is 80% of its calls in the last 60 seconds, the frequency score for `account_search` spikes. The Z-score measures how many standard deviations the current rate is from the historical mean.

**Parameter structure anomaly (Jaccard distance)**

Compares the parameter keys in the current call against the most common parameter structure for that tool in the agent's history.

If an agent normally calls `account_search` with `{"query": "alice"}` and suddenly starts calling it with `{"query": "alice", "limit": 10000, "export": true}`, the parameter structure has diverged. The Jaccard distance between the current key set and the historical key set measures that divergence.

This catches cases where the agent is being used to extract more data per call than normal even when the frequency looks fine.

**Final score**

```
anomaly_score = max(frequency_score, parameter_score)
```

The higher of the two signals determines the final score. Thresholds:

- Score >= 0.6: alert logged, call allowed
- Score >= 0.9: call blocked with `ANOMALY_BLOCKED`

Both thresholds are configurable.

---

## The warmup period

During warmup, blocking is suppressed even if the score crosses the threshold. Calls are still observed and the baseline is still built. Alerts are still logged. But calls are not rejected until the baseline has enough data to be meaningful.

The warmup period ends when the time-weighted observation count reaches a minimum threshold. This prevents false positives on brand new agents whose first few calls might look anomalous simply because there is no history yet.

---

## What gets logged

Every call that triggers an anomaly signal above the alert threshold is written to the authorization log with:

- The agent subject
- The tool name
- The anomaly score
- Which signal triggered (frequency, parameter structure, or both)
- The specific reasons (call rate X times above baseline, parameter structure diverged by Y)

This gives your security team the context to investigate: when did the pattern change, what changed, and whether it warrants revocation of the agent's credentials.

---

## Limitations

The anomaly detector catches behavioral deviation from an agent's own baseline. It does not catch:

- An attacker who behaves exactly like the legitimate agent would
- A new attack pattern on an agent that has never established a baseline
- Prompt injections that cause the model to do unusual things without changing its call patterns

These limitations are fundamental to behavioral detection. The detector is one layer in a defense-in-depth approach, not a complete solution on its own.

---

## References

- Hunter, J.S. (1986). The Exponentially Weighted Moving Average. Journal of Quality Technology, 18(4), 203-210.
- [Jaccard similarity coefficient](https://en.wikipedia.org/wiki/Jaccard_index)
- [Identity Management for Agentic AI, arXiv:2510.25819](https://arxiv.org/abs/2510.25819)
