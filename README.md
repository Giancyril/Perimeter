# Security Operations Agent

A production-grade, AI-augmented Security Operations platform built for enterprise SOC teams. Features a LangGraph-powered autonomous investigation agent, MITRE ATT&CK-mapped event correlation, hybrid deterministic-plus-LLM severity scoring with tamper-proof floor enforcement, STIX 2.1 threat intelligence sharing, multi-source IOC enrichment pipelines, forensic chain-of-custody manifests, regulatory compliance disclosure (GDPR 72h, SEC Form 8-K, HIPAA), SOAR-style automated playbook execution with human-in-the-loop approval gates, Slack/PagerDuty escalation dispatch, executive briefing generation, a React 19 Sentinel-inspired SOC dashboard, adversarial prompt-injection defenses, Helm/Kubernetes deployment, and a GitHub Actions evaluation quality gate.

## Features

### Core Pipeline
- **Alert Ingestion**: Wazuh webhook receiver with adapters for Splunk, Elastic, and Microsoft Sentinel -- normalized to a unified OCSF/ECS schema with SHA-256 alert deduplication
- **Event Correlation**: Sliding time-window entity grouping by source/dest IP, user, and host with MITRE ATT&CK tactic/technique mapping
- **LangGraph Investigation Agent**: Multi-step stateful investigation graph with AbuseIPDB, VirusTotal, SIEM log search, and asset criticality lookups wrapped behind a strict untrusted-data boundary and execution step limiters
- **Hybrid Severity Scoring**: Deterministic formula combined with structured LLM reasoning, plus a hardened non-downgrade floor enforcer that prevents adversarial quiet downgrades
- **Evidence-Linked Reporting**: Structured incident timelines with full evidence traceability, Markdown and PDF exports, forensic chain-of-custody manifests, and STIX 2.1 JSON bundles

### Advanced Features

#### Severity Engine (Day 4)
- **Risk Matrix Scorer**: CVSS-inspired multi-factor matrix combining asset criticality, ATT&CK technique severity, and environmental context
- **Environmental Drift Compensator**: Off-hours, maintenance window, and temporal sensitivity adjustments that widen severity windows during high-risk periods
- **Threat Actor Weighting**: Sophistication and capability scoring for known APT groups, ransomware operators, and insider threat profiles
- **Business Impact Assessor**: Critical workflow disruption scoring with SLA deadline calculation and financial exposure estimation
- **Historical Calibration Engine**: Analyst feedback loop with bias offset correction to continuously improve scoring accuracy
- **Composite Orchestrator**: Single entry point integrating all five scoring dimensions into a unified CompositeSeverityResult
- **Floor Enforcement**: Tamper-proof audit proof system preventing any LLM or external actor from quietly downgrading a confirmed high-severity incident

#### Report Generation Engine (Day 5)
- **STIX 2.1 Exporter**: Automated threat intelligence sharing bundles compatible with TAXII feeds and ISACs
- **Executive Briefing Generator**: Financial impact quantification, SEC Form 8-K disclosure assessment, and board-ready summaries
- **MITRE ATT&CK Graph Visualizer**: Mermaid kill-chain diagrams and ASCII attack graphs for analyst briefings
- **Forensic Chain-of-Custody**: Cryptographic SHA-256 verification manifests for legal admissibility
- **Regulatory Compliance Engine**: Automated GDPR 72-hour notification, SEC Form 8-K, and HIPAA breach disclosure drafting
- **Root Cause Analyzer**: 5-Whys methodology with MITRE D3FEND countermeasure mapping
- **Multi-Channel Notification Dispatcher**: Slack Block Kit and Microsoft Teams Adaptive Card formatters
- **Historical Report Diff Engine**: Tracks incident evolution across report revisions with semantic change detection
- **Unified Report Orchestrator**: Multi-stage pipeline producing analyst dossiers, executive packages, and compliance bundles in a single pass

#### Escalation and Human-in-the-Loop (Phase 6)
- **Slack and PagerDuty Dispatch**: Structured escalation webhooks with on-call routing and severity-tiered notification policies
- **LangGraph Interrupt Gate**: Server-side approval interrupt for host isolation and IP blocking requiring explicit human analyst sign-off
- **Proposed Action Ledger**: Append-only audit trail of every proposed, approved, rejected, and rolled-back containment action
- **Risk-Tiered Approval**: LOW actions can be pre-approved by policy; CRITICAL actions require senior analyst justification and dual confirmation

### SOC Dashboard
- **Incident Queue**: Dense sortable and filterable incident table with real-time severity badges and escalation status
- **Detail Timeline**: Full investigation timeline with evidence links, entity correlation panel, and agent reasoning trace
- **Response Approval Banner**: Prominent human-approval UI for pending containment actions with risk-level context
- **Entity Correlation Panel**: Graph-style view connecting source IPs, destination hosts, users, and ATT&CK techniques across correlated alerts

### Security Design Invariants
- **Log content is attacker-controlled input**: Usernames, user-agent strings, URLs, and hostnames in SIEM logs can carry prompt-injection payloads. Everything pulled from logs is escaped, delimited, and treated as untrusted data before reaching the LLM
- **The LLM cannot quietly downgrade a real threat**: Severity is calculated deterministically from rules, asset criticality, threat intelligence, and ATT&CK mapping. The LLM can explain or raise severity but cannot lower severity below the deterministic floor without a logged, human-authorized override

---

## Architecture

```
+------------------+   +-------------------+   +----------------------+
|    INGEST         |-->|    CORRELATE        |-->|    INVESTIGATE        |
| (Wazuh/Splunk/   |   | (entity grouping   |   | (LangGraph agent:    |
|  Elastic/        |   |  by IP/user/host;  |   |  log search,         |
|  Sentinel;       |   |  ATT&CK tactic/    |   |  AbuseIPDB,          |
|  OCSF/ECS norm)  |   |  technique map)    |   |  VirusTotal, assets) |
+------------------+   +-------------------+   +----------------------+
                                                           |
           +-----------------------------------------------+
           v
+------------------+   +-------------------+   +----------------------+
|    SEVERITY       |-->|    REPORT          |-->|    ESCALATE           |
| (deterministic   |   | (STIX, executive   |   | (Slack/PagerDuty;    |
|  score + LLM;    |   |  briefing, MITRE   |   |  LangGraph human-    |
|  floor enforce;  |   |  graph, forensic   |   |  in-the-loop gate;   |
|  composite       |   |  CoC, compliance   |   |  host isolation /    |
|  orchestrator)   |   |  disclosure)       |   |  IP block approval)  |
+------------------+   +-------------------+   +----------------------+
```

PostgreSQL acts as the persistent system of record underneath all components: alerts, incidents, correlated entities, investigation logs, and an append-only audit trail.

---

## Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Agent Orchestration | LangGraph | Multi-step stateful investigation graph with server-side interrupt/checkpoint model for human-approval gates |
| Backend API | FastAPI | Async webhook receivers for multi-source SIEM ingestion, parallel threat-intel calls, and high-performance incident APIs |
| SIEM Integration | Wazuh + Splunk, Elastic, Sentinel adapters | Unified AlertSource adapter interface over an open-source self-hostable SIEM |
| Database | PostgreSQL | Normalized alerts, correlated incidents, entity graph relationships, and append-only audit logs |
| Enrichment Sources | AbuseIPDB, VirusTotal, GeoIP, Asset/User Context | Grounded threat evidence instead of LLM hallucinations from alert text alone |
| Threat Intelligence | STIX 2.1/TAXII, MITRE ATT&CK, MITRE D3FEND | Structured TI sharing, technique mapping, and countermeasure recommendations |
| Frontend Dashboard | React 19 + TypeScript + Vite | Sentinel-inspired high-contrast dark SOC dashboard with dense incident queues, timeline graphs, entity panels, and response approval banners |
| Containerization | Docker Compose + Helm/Kubernetes | Local dev and production-grade deployment with bitnami PostgreSQL sub-chart |
| CI/CD | GitHub Actions | Evaluation quality gate enforcing minimum detection accuracy before merge |

---

## Monorepo Layout

```
Security Operations Agent/
+-- backend/
|   +-- app/                # FastAPI: webhooks, incident API
|   +-- ingestion/          # AlertSource adapters, normalizer, deduplication
|   +-- correlation/        # Entity grouping, sliding time windows, ATT&CK mapping
|   +-- agent/              # LangGraph investigation graph, tool nodes, untrusted-input wrapper
|   +-- severity/           # Deterministic scorer, composite orchestrator, floor enforcer
|   |   +-- scorer.py           # DeterministicScorer with score_with_composite()
|   |   +-- floor_enforcer.py   # Tamper-proof non-downgrade invariant with audit proofs
|   |   +-- risk_matrix.py      # CVSS-inspired multi-factor risk matrix
|   |   +-- drift_compensator.py# Environmental and temporal sensitivity adjustments
|   |   +-- actor_weighter.py   # Threat actor capability and sophistication weighting
|   |   +-- business_impact.py  # Business disruption and SLA impact assessment
|   |   +-- calibration.py      # Historical analyst feedback calibration engine
|   |   +-- composite_scorer.py # Unified composite orchestrator
|   |   +-- report_generator.py # Markdown/JSON analyst report generator
|   +-- reporting/          # Evidence-linked report pipeline
|   |   +-- stix_exporter.py        # STIX 2.1 JSON bundles
|   |   +-- executive_briefing.py   # Board-ready financial impact summaries
|   |   +-- attack_graph.py         # MITRE ATT&CK kill-chain visualizer
|   |   +-- chain_of_custody.py     # Forensic SHA-256 chain-of-custody manifests
|   |   +-- compliance_engine.py    # GDPR/SEC/HIPAA disclosure drafting
|   |   +-- root_cause_analyzer.py  # 5-Whys + MITRE D3FEND countermeasures
|   |   +-- dispatch.py             # Slack Block Kit + Teams Adaptive Card dispatch
|   |   +-- report_diff.py          # Historical report diff and revision tracking
|   |   +-- orchestrator.py         # Unified multi-stage report orchestrator
|   +-- response/           # Proposed actions, human approval gate, execution client
|   +-- requirements.txt
+-- frontend/               # React 19 + Vite + TypeScript SOC operations UI
+-- eval/                   # Labeled incidents, attack-replay harness, accuracy tracking
+-- infra/                  # Docker Compose, Helm charts
+-- scripts/                # SOC audit demo scripts and commit helpers
+-- tests/                  # Pytest test suites
+-- README.md
```

---

## Phased Implementation Roadmap

- [x] **Phase 0: Project Scaffolding (Day 0-1)**: Monorepo layout, FastAPI backend skeleton, React 19 Vite TypeScript frontend, Docker Compose PostgreSQL + alert simulator, initial 10-incident labeled evaluation dataset
- [x] **Phase 1: Alert Ingestion and Normalization (Day 1-5)**: Wazuh webhook receiver, normalized alert schema (OCSF/ECS), SHA-256 alert deduplication
- [x] **Phase 2: Event Correlation and ATT&CK Mapping (Day 5-10)**: Time-window entity grouping (source/dest IP, user, host), MITRE ATT&CK tactic/technique mapping
- [x] **Phase 3: LangGraph Investigation Agent (Day 10-17)**: Tool nodes (SIEM search, AbuseIPDB, VirusTotal, asset criticality), untrusted-data boundary wrapper, execution step limiters
- [x] **Phase 4: Hybrid Severity Scoring and Floor Enforcement (Day 17-21)**: Deterministic formula, LLM reasoning contribution, composite orchestrator, strict floor enforcement preventing downgrades
- [x] **Phase 5: Evidence-Linked Report Generation (Day 21-24)**: STIX 2.1 bundles, executive briefings, MITRE ATT&CK graphs, forensic chain-of-custody, GDPR/SEC/HIPAA compliance disclosure, multi-channel notification dispatch, historical report diffing, unified orchestrator
- [x] **Phase 6: Escalation and Human-in-the-Loop Response Gate (Day 24-28)**: Slack/PagerDuty webhook dispatch, LangGraph server-side interrupt approval gate for host isolation and IP blocking
- [x] **Phase 7: Frontend SOC Dashboard (Day 28-34)**: Incident queue table, detail timeline, entity correlation panel, approval banner
- [x] **Phase 8: Evaluation, Adversarial and Failure Testing (Day 34-38)**: Attack replay evaluation against labeled set, prompt injection defenses, external API failure mode testing
- [x] **Phase 9: Deployment and CI/CD (Day 38-41)**: Container packaging, Helm charts, GitHub Actions evaluation quality gate

---

## Quickstart and Local Setup

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker and Docker Compose
- PostgreSQL 15+ (or use the bundled Compose stack)

### 1. Environment Configuration

`ash
cp .env.example .env
`

Fill in: OPENAI_API_KEY, ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, SLACK_WEBHOOK_URL, PAGERDUTY_INTEGRATION_KEY, DATABASE_URL

### 2. Backend Setup

`powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn backend.app.main:app --reload --port 8000
`

| Endpoint | URL |
|---|---|
| API Docs (Swagger) | http://localhost:8000/docs |
| Health Check | http://localhost:8000/health |
| Wazuh Alert Webhook | http://localhost:8000/api/v1/alerts/webhook/wazuh |
| Incident API | http://localhost:8000/api/v1/incidents |

### 3. Frontend Setup

`powershell
cd frontend
npm install
npm run dev
`

SOC Dashboard: http://localhost:5173

### 4. Full Stack via Docker Compose

`ash
make docker-up
`

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000/docs

### 5. Kubernetes / Helm

`ash
helm dependency update infra/helm/secops-agent
helm install secops-agent infra/helm/secops-agent --set secrets.openaiApiKey="sk-..." --set postgresql.auth.password="strong-pass"
`

### 6. Run Tests

`powershell
pytest -v
pytest tests/test_day4_severity.py -v
pytest tests/test_day5_reporting.py -v
pytest tests/test_prompt_injection.py -v
`

---

## SOC Audit Demo

`powershell
python scripts/soc_audit_demo.py
python scripts/day5_reporting_demo.py
`

---

## License

MIT