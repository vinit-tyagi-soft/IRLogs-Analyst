from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .models import Event


def build_timeline(events: list[Event]) -> list[Event]:
    return sorted(events, key=lambda e: (e.timestamp is None, e.timestamp, e.event_id))


def correlate_events(events: list[Event]) -> dict[str, Any]:
    entity_indexes: dict[str, dict[str, list[str]]] = {
        "host": defaultdict(list),
        "user": defaultdict(list),
        "process": defaultdict(list),
        "ip": defaultdict(list),
        "file_hash": defaultdict(list),
    }
    edge_counter: Counter[tuple[str, str, str, str]] = Counter()

    for event in events:
        entities = {
            "host": event.host,
            "user": event.user,
            "process": event.process,
            "ip": event.ip,
            "file_hash": event.file_hash,
        }
        for etype, value in entities.items():
            if value:
                entity_indexes[etype][value].append(event.event_id)

        pairs = [
            ("host", event.host, "user", event.user),
            ("host", event.host, "process", event.process),
            ("user", event.user, "ip", event.ip),
            ("process", event.process, "file_hash", event.file_hash),
        ]
        for left_t, left_v, right_t, right_v in pairs:
            if left_v and right_v:
                edge_counter[(left_t, left_v, right_t, right_v)] += 1

    top_edges = sorted(edge_counter.items(), key=lambda x: x[1], reverse=True)[:20]
    return {
        "entity_indexes": {k: dict(v) for k, v in entity_indexes.items()},
        "graph_summary": [
            {
                "left_type": edge[0],
                "left_value": edge[1],
                "right_type": edge[2],
                "right_value": edge[3],
                "count": count,
            }
            for edge, count in top_edges
        ],
    }
