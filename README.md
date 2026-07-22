<h1 align="center">🛡️ SENTINEL</h1>

<p align="center">
  <b>AI-Powered Cyber Defense Intelligence Platform</b><br>
  A multi-agent pipeline that turns raw security logs into analyst-ready threat intelligence.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/LangGraph-8E44FF?style=flat-square">
  <img src="https://img.shields.io/badge/Groq-F55036?style=flat-square">
  <img src="https://img.shields.io/badge/Llama%203.3%2070B-00A8FF?style=flat-square">
  <img src="https://img.shields.io/badge/Streamlit-FF4B4B?style=flat-square&logo=streamlit&logoColor=white">
  <img src="https://img.shields.io/badge/status-v1%20working-00D084?style=flat-square">
</p>

---

## The Problem

Security teams drown in log volume. A mid-sized organization generates millions of events daily across firewalls, intrusion detection systems, endpoints, and authentication services. Most of it is noise. The signal — the handful of correlated events that indicate an actual intrusion — gets buried.

Traditional SIEM tools apply static rules and emit alerts, not understanding. An analyst still has to read the alerts, connect them across sources, judge severity, and write up what happened.

## What SENTINEL Does

SENTINEL runs a LangGraph agent pipeline over normalized logs. Each agent handles one stage of the analyst workflow, passing structured state forward. The output is a written intelligence report with correlated findings, risk scores, and remediation guidance.

**Worked example.** Given an SSH auth log containing repeated failed logins from a single external IP, followed by one success and a `sudo` escalation, SENTINEL detects the brute-force pattern, correlates it with the subsequent success into one incident, scores it critical, and writes it up with the attacking IP and compromised account named.

---

## Pipeline

```
ingest ──> detect ──> correlate ──> report
```

| Stage | Type | Responsibility |
|---|---|---|
| **Ingest** | Deterministic | Parses raw logs into a normalized event schema |
| **Detect** | LLM agent | Flags suspicious patterns in normalized events |
| **Correlate** | LLM agent | Groups detections into scored incidents |
| **Report** | LLM agent | Composes the analyst-facing intelligence report |

Ingestion is deliberately not an LLM call. Parsing is a solved problem, and determinism there is worth more than flexibility — it keeps token costs down and stops the model hallucinating fields that were never in the log.

State flows forward, so each agent works with what its predecessors established rather than re-reading raw input.

---

## Supported Log Sources

| Source | Status | Format |
|---|---|---|
| Authentication | ✅ Working | Linux `auth.log` / sshd syslog |
| Firewall | ✅ Working | Timestamped action/protocol/endpoint records |
| IDS/IPS | 🔜 Planned | — |
| Endpoint telemetry | 🔜 Planned | — |

---

## Getting Started

### Prerequisites

- Python 3.10+
- A Groq API key — free at [console.groq.com](https://console.groq.com)

### Installation

```bash
git clone https://github.com/Humaira-Muqades/sentinel-cyber-intelligence.git
cd sentinel-cyber-intelligence

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Configuration

```bash
cp .env.example .env
```

Then add your key to `.env`:

```
GROQ_API_KEY=your_key_here
MODEL_NAME=llama-3.3-70b-versatile
```

### Running

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`. The sample logs are loaded by default, so you can run an analysis immediately without supplying your own data.

### Tests

```bash
python -m pytest tests/ -v
```

---

## Project Structure

```
sentinel-cyber-intelligence/
├── app.py                    # Streamlit interface
├── requirements.txt
├── .env.example
│
├── src/
│   ├── state.py              # Shared state schema
│   ├── parsers.py            # Deterministic log parsing
│   ├── llm.py                # Groq client wrapper
│   ├── graph.py              # LangGraph StateGraph
│   └── agents/
│       ├── detection.py
│       ├── correlation.py
│       └── reporting.py
│
├── data/samples/             # Sample logs for demo runs
├── docs/diagrams/            # Architecture diagrams
└── tests/
```

---

## Design Notes

**Why separate detection from correlation.** A single failed login is noise. Forty of them followed by a success is an incident. Splitting the two stages means the detection agent can be liberal about flagging without producing a flood of alerts, because correlation collapses related findings into one scored incident.

**Failure handling.** Each agent catches its own exceptions and writes to a shared `errors` list rather than raising. One failed stage degrades the output instead of killing the run — the report still gets written, just with less to work with.

**Token budget.** Detection caps input at 200 events per run. Beyond that, the prompt cost grows faster than the marginal insight.

---

## Roadmap

The full design calls for a seven-agent pipeline. v1 implements the three that carry the most weight.

- [ ] **Enrichment agent** — IP reputation, asset criticality, user role context
- [ ] **Risk scoring agent** — split scoring out of correlation into its own stage
- [ ] **Remediation agent** — dedicated mitigation planning
- [ ] IDS/IPS and endpoint log parsers
- [ ] MITRE ATT&CK technique mapping
- [ ] Persistent incident history across runs
- [ ] Batch processing for large log volumes

---

## License

MIT — see [LICENSE](LICENSE).

---

## Author

**Humaira Muqades** — AI Engineer, PhD scholar researching DeepFake detection

[LinkedIn](https://www.linkedin.com/in/humaira-muqades-rana/) · [GitHub](https://github.com/Humaira-Muqades) · humaramuqdes@gmail.com
