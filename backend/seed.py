"""
Seed script: Populates the in-memory engine with realistic security scenarios.
Usage:
    python -m backend.seed
"""
from backend.evaluation.dataset import BENCHMARK_SCENARIOS
from backend.ingestion.engine import ingestion_engine
from backend.correlation.engine import correlation_engine

def seed():
    print(f"[*] Ingesting {len(BENCHMARK_SCENARIOS)} benchmark scenarios...")
    alert_count = 0
    for scenario in BENCHMARK_SCENARIOS:
        for alert in scenario.alerts:
            ingestion_engine.ingest(alert)
            alert_count += 1

    incidents = correlation_engine.list_incidents()
    print(f"[+] Successfully ingested {alert_count} alerts!")
    print(f"[+] Generated {len(incidents)} correlated security incidents:")
    for inc in incidents:
        print(f"    - [{inc.incident_id}] Severity: {inc.deterministic_floor.value:<8} "
              f"Alerts: {len(inc.alerts):<2} Primary Entity: {inc.primary_entity} | Title: {inc.title}")

if __name__ == "__main__":
    seed()
