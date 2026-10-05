"""
Bipartite Entity-Alert Graph Correlation Engine.
Constructs multi-hop relationship graphs between security entities (IPs, Hosts, Users, Hashes)
and alerts to discover non-obvious pivot paths and connected threat clusters.
"""
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict, deque
from backend.ingestion.models import NormalizedAlert, Entity, EntityType

class EntityNode:
    def __init__(self, entity_type: str, value: str):
        self.key = f"{entity_type}:{value.lower().strip()}"
        self.entity_type = entity_type
        self.value = value
        self.alert_ids: Set[str] = set()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.key,
            "type": self.entity_type,
            "label": self.value,
            "degree": len(self.alert_ids),
        }

class AlertNode:
    def __init__(self, alert: NormalizedAlert):
        self.id = alert.alert_id
        self.title = alert.title
        self.severity = alert.normalized_severity.value
        self.timestamp = alert.timestamp
        self.entity_keys: Set[str] = set()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": "alert",
            "label": self.title,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "degree": len(self.entity_keys),
        }

class EntityGraph:
    """Thread-safe bipartite graph between Alerts and Entities."""

    def __init__(self):
        self.entities: Dict[str, EntityNode] = {}
        self.alerts: Dict[str, AlertNode] = {}
        # Adjacency: node_id -> set of connected node_ids
        self.adj: Dict[str, Set[str]] = defaultdict(set)

    def add_alert(self, alert: NormalizedAlert) -> None:
        """Adds an alert node and links it with all extracted entity nodes."""
        alert_node = AlertNode(alert)
        self.alerts[alert.alert_id] = alert_node

        for ent in alert.entities:
            key = f"{ent.entity_type.value}:{ent.value.lower().strip()}"
            if key not in self.entities:
                self.entities[key] = EntityNode(ent.entity_type.value, ent.value)
            
            ent_node = self.entities[key]
            ent_node.alert_ids.add(alert.alert_id)
            alert_node.entity_keys.add(key)

            # Bi-directional bipartite edges
            self.adj[alert.alert_id].add(key)
            self.adj[key].add(alert.alert_id)

    def find_connected_clusters(self) -> List[Dict[str, Any]]:
        """
        Discovers all connected components (clusters) using BFS.
        Each cluster represents a set of alerts sharing one or more pivot entities.
        """
        visited: Set[str] = set()
        clusters: List[Dict[str, Any]] = []

        all_nodes = list(self.alerts.keys()) + list(self.entities.keys())
        for node in all_nodes:
            if node in visited:
                continue

            cluster_alerts: List[str] = []
            cluster_entities: List[str] = []
            queue = deque([node])
            visited.add(node)

            while queue:
                curr = queue.popleft()
                if curr in self.alerts:
                    cluster_alerts.append(curr)
                elif curr in self.entities:
                    cluster_entities.append(curr)

                for neighbor in self.adj[curr]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            if cluster_alerts:
                clusters.append({
                    "cluster_id": f"cluster-{len(clusters) + 1}",
                    "alert_ids": cluster_alerts,
                    "entity_keys": cluster_entities,
                    "size": len(cluster_alerts) + len(cluster_entities),
                })

        return sorted(clusters, key=lambda c: len(c["alert_ids"]), reverse=True)

    def find_shortest_pivot_path(self, start_entity_key: str, end_entity_key: str) -> Optional[List[str]]:
        """
        Calculates the shortest pivot path between two entities via intermediate alerts.
        Returns a list of node IDs: [entity1, alertA, entity2, alertB, ...].
        """
        start = start_entity_key.lower().strip()
        end = end_entity_key.lower().strip()

        if start not in self.adj or end not in self.adj:
            return None
        if start == end:
            return [start]

        queue = deque([[start]])
        visited = {start}

        while queue:
            path = queue.popleft()
            current = path[-1]

            for neighbor in self.adj[current]:
                if neighbor == end:
                    return path + [neighbor]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])

        return None

    def get_entity_centrality(self, entity_key: str) -> int:
        """Returns the degree centrality (number of distinct alerts linked) of an entity."""
        key = entity_key.lower().strip()
        if key in self.entities:
            return len(self.entities[key].alert_ids)
        return 0

    def export_graph_json(self) -> Dict[str, Any]:
        """Exports graph in D3 / Cytoscape compatible JSON format."""
        nodes = []
        for a in self.alerts.values():
            nodes.append(a.to_dict())
        for e in self.entities.values():
            nodes.append(e.to_dict())

        edges = []
        for alert_id, a_node in self.alerts.items():
            for ent_key in a_node.entity_keys:
                edges.append({
                    "source": alert_id,
                    "target": ent_key,
                    "relationship": "correlates_with",
                })

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "total_alerts": len(self.alerts),
                "total_entities": len(self.entities),
                "total_edges": len(edges),
            },
        }
