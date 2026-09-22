# 🛡️ AI Network Traffic Analyzer & Threat Investigator

**Traffic Sentinel** — An AI-assisted network security monitoring and investigation dashboard built with Python.

---

## 1. Problem Statement

Network security monitoring requires analyzing large volumes of traffic data to identify suspicious behavior. Manual analysis is time-consuming and requires specialized expertise. This project automates traffic analysis using deterministic detection rules, machine learning anomaly detection, and GenAI-powered investigation assistance.

## 2. Objectives

- Monitor network traffic metadata and flows
- Detect suspicious behavior using rule-based detection
- Identify anomalies using machine learning (Isolation Forest)
- Enrich traffic data with threat intelligence
- Provide AI-assisted alert explanation and investigation
- Generate security health reports
- Offer a polished, SOC-style dashboard for visualization

## 3. Features

| Feature | Description |
|---------|-------------|
| **Traffic Monitoring** | Capture and analyze network flow metadata |
| **Rule-Based Detection** | Port scan, high frequency, DNS anomaly, unusual time, failed connections |
| **Risk Scoring** | Transparent, configurable risk scoring engine (0-100) |
| **Anomaly Detection** | Isolation Forest ML model for behavioral deviation |
| **Threat Intelligence** | IP reputation enrichment (mock + API) |
| **AI Security Analyst** | GPT-powered alert explanation, investigation chat, skeptic mode |
| **Event Correlation** | AI-driven analysis of related security events |
| **Simulation Mode** | 6 synthetic traffic scenarios for safe demo |
| **Investigation Cases** | Create and manage investigation cases with evidence |
| **Timeline** | Chronological event visualization |
| **Network Graph** | Entity relationship visualization (NetworkX + Plotly) |
| **Security Health Scan** | 15-day period comparison with AI summary |
| **PDF Reports** | Investigation report generation with ReportLab |
| **Dashboard** | Dark, professional SOC-style Streamlit UI |

## 4. Architecture

```
Network Traffic
      ↓
Packet Capture (Scapy - optional)
      ↓
Feature Extraction
      ↓
Rule-Based Detection + Anomaly Detection + Threat Intelligence
      ↓
Risk Scoring Engine
      ↓
Alert Generation
      ↓
GenAI Security Analyst (Explanation / Investigation / Correlation)
      ↓
Dashboard (Streamlit)
```

**Core Principle:** Python detects and structures evidence. GenAI interprets, explains, and communicates that evidence.

## 5. Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| Database | SQLite |
| Packet Capture | Scapy (optional) |
| Data Processing | Pandas, NumPy |
| Machine Learning | scikit-learn (Isolation Forest) |
| Threat Intelligence | Mock DB + Optional API |
| GenAI | OpenAI GPT API |
| Dashboard | Streamlit |
| Charts | Plotly |
| Graphs | NetworkX |
| Reports | ReportLab |
| Config | python-dotenv |

## 6. Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd traffic_sentinel

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Mac/Linux

# Install dependencies
pip install -r requirements.txt
```

## 7. Environment Variables

Create a `.env` file in the project root:

```env
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4o-mini
THREAT_INTEL_API_KEY=
```

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Optional | OpenAI API key for AI features |
| `OPENAI_MODEL` | Optional | GPT model to use (default: gpt-4o-mini) |
| `THREAT_INTEL_API_KEY` | Optional | Threat intelligence API key |

**Without API keys:** The dashboard, simulation, detection, and all non-AI features work perfectly. AI features show a configuration message.

## 8. How to Run

```bash
streamlit run app.py
```

The dashboard opens at `http://localhost:8501`.

## 9. Simulation Mode

1. Navigate to **🎮 Simulation** in the sidebar
2. Select a scenario (e.g., "Port Scan")
3. Click **▶️ Run Simulation**
4. View generated alerts and flows
5. Go to **🚨 Alerts** to see detection results
6. Click **🤖 Explain Alert** for AI analysis (requires API key)

### Available Scenarios

| Scenario | Description |
|----------|-------------|
| Normal Traffic | Typical web browsing and DNS queries |
| Port Scan | Rapid multi-port contact pattern |
| High Connection Frequency | Excessive connections in short period |
| DNS Anomaly | Queries to suspicious domains |
| Unusual Outbound Traffic | Large transfers to suspicious IPs |
| Brute Force Pattern | Repeated failed auth attempts |

## 10. Live Mode

Live packet capture requires:
- Administrator/root privileges
- Scapy installed (`pip install scapy`)
- Appropriate network interface permissions

In live mode, the system captures packets via Scapy, builds flows, and runs them through the same detection pipeline.

## 11. GenAI Architecture

```
User Question
      ↓
SecurityAnalyst.chat()
      ↓
System Prompt + Context + Tools
      ↓
OpenAI API (GPT model)
      ↓
Tool Calls (optional)
      ↓
Python Tools query SQLite
      ↓
Results returned to LLM
      ↓
AI Response grounded in evidence
```

**Key Design:** The LLM never directly accesses the database. Python tools query the database and return structured data to the LLM for interpretation.

## 12. Database Schema

- **traffic_flows** — Network flow records with metadata and risk scores
- **alerts** — Security alerts with severity, detection reasons, and evidence
- **entities** — IP addresses, domains, and other network entities
- **relationships** — Connections between entities
- **investigations** — Investigation cases with status and conclusions
- **evidence** — Evidence items linked to investigations
- **baselines** — Historical traffic baselines per host

## 13. Risk Scoring

| Score Range | Severity | Description |
|------------|----------|-------------|
| 0-20 | Normal | No suspicious indicators |
| 21-40 | Low | Minor anomalies detected |
| 41-60 | Suspicious | Multiple indicators triggered |
| 61-80 | High | Strong indicators of concern |
| 81-100 | Critical | Multiple high-confidence indicators |

**Weights:** Configurable in `config.py`. Risk scores are heuristic outputs, not proof of compromise.

## 14. Detection Rules

| Rule | Trigger | Weight |
|------|---------|--------|
| Port Scan | >15 unique ports contacted | +25 |
| High Frequency | >50 connections in period | +15 |
| Unusual Time | Activity 1-5 AM | +10 |
| DNS Anomaly | Suspicious TLD/domain patterns | +15 |
| Failed Connections | >5 failed attempts | +15 |
| Traffic Anomaly | ML anomaly score >0.5 | +20 |
| Reputation Concern | Known suspicious IP | +35 |

## 15. Project Structure

```
traffic_sentinel/
├── app.py                  # Main Streamlit application
├── config.py               # Configuration and constants
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
├── database/
│   ├── db.py               # SQLite database operations
│   ├── models.py           # Data models
│   └── schema.sql          # Database schema
├── capture/
│   ├── packet_capture.py   # Scapy packet capture
│   └── flow_builder.py     # Flow construction from packets
├── detection/
│   ├── __init__.py         # Rule-based detection engine
│   ├── anomaly_detector.py # Isolation Forest ML
│   └── risk_engine.py      # Risk score calculation
├── intelligence/
│   └── threat_intelligence.py  # IP reputation enrichment
├── ai/
│   ├── security_agent.py   # GenAI Security Analyst
│   ├── prompts.py          # AI system prompts
│   └── tools.py            # Python tools for AI
├── simulation/
│   ├── simulator.py        # Simulation engine
│   └── scenarios.py        # Synthetic traffic generators
├── analytics/
│   ├── statistics.py       # Traffic statistics
│   └── baseline.py         # Historical baseline
├── reports/
│   └── report_generator.py # PDF report generation
├── ui/                     # UI modules
└── data/                   # Database and reports
```

## 16. Limitations

- A normal browser cannot inspect all host traffic
- Packet visibility depends on interface permissions and OS configuration
- Encrypted traffic limits payload-level inspection
- Risk scores are heuristic/model outputs, not proof of compromise
- Anomaly detection can generate false positives
- Threat intelligence reputation is contextual and may be incomplete
- GenAI explanations are advisory and should be grounded in evidence
- Live capture requires admin privileges and Scapy

## 17. Security & Privacy

- No raw packet payloads stored by default
- API keys stored in `.env`, never in source code
- All analysis performed locally
- GenAI receives only metadata, not raw packets
- Mock threat intelligence used when no API key configured

## 18. Future Enhancements

- Real-time packet capture dashboard
- Deep packet inspection for unencrypted protocols
- Integration with real threat intelligence feeds (VirusTotal, AbuseIPDB)
- Email/Syslog alert forwarding
- Multi-user authentication
- Historical data export
- Custom detection rule editor
- Automated response actions

## 19. Placement/Viva Topics

This project demonstrates:
- **Python:** OOP, modules, exception handling, APIs, file handling
- **Networking:** TCP, UDP, DNS, IP, ports, packets, flows
- **Cybersecurity:** Anomaly detection, threat indicators, risk scoring, incident investigation
- **ML:** Isolation Forest, feature engineering, anomaly scoring
- **GenAI:** LLM integration, prompt engineering, tool calling, hallucination prevention
- **Database:** SQLite, SQL queries, historical analysis
- **UI:** Streamlit, Plotly, responsive dashboard design
