"""Cycle summarization helpers for Semantic Core v0.1.0."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from apk_agent.tools.semantic_core.identity import stable_identity


_ELIGIBLE_EDGE_KINDS = {"write", "derive", "project", "serialize", "deserialize"}
_ELIGIBLE_NODE_KINDS = {"field", "boundary"}


def summarize_cycles(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    node_ids = {
        node.get("id")
        for node in nodes
        if node.get("id") and node.get("kind") in _ELIGIBLE_NODE_KINDS
    }
    adjacency: dict[str, list[str]] = defaultdict(list)
    eligible_edges: list[dict[str, Any]] = []
    for edge in edges:
        if edge.get("kind") not in _ELIGIBLE_EDGE_KINDS:
            continue
        source = edge.get("source")
        target = edge.get("target")
        if source in node_ids and target in node_ids:
            adjacency[source].append(target)
            eligible_edges.append(edge)

    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def _strongconnect(node_id: str) -> None:
        nonlocal index
        indices[node_id] = index
        lowlinks[node_id] = index
        index += 1
        stack.append(node_id)
        on_stack.add(node_id)

        for neighbor in adjacency.get(node_id, []):
            if neighbor not in indices:
                _strongconnect(neighbor)
                lowlinks[node_id] = min(lowlinks[node_id], lowlinks[neighbor])
            elif neighbor in on_stack:
                lowlinks[node_id] = min(lowlinks[node_id], indices[neighbor])

        if lowlinks[node_id] != indices[node_id]:
            return

        component: list[str] = []
        while stack:
            member = stack.pop()
            on_stack.discard(member)
            component.append(member)
            if member == node_id:
                break
        if len(component) > 1:
            components.append(sorted(component))
        elif component and component[0] in adjacency and component[0] in adjacency[component[0]]:
            components.append(component)

    for node_id in sorted(node_ids):
        if node_id not in indices:
            _strongconnect(node_id)

    summaries: list[dict[str, Any]] = []
    for component_nodes in sorted(components, key=lambda item: item[0]):
        component_edges = sorted(
            edge.get("id", "")
            for edge in eligible_edges
            if edge.get("source") in component_nodes and edge.get("target") in component_nodes
        )
        summaries.append({
            "component_id": stable_identity("cycle", component_nodes),
            "node_ids": component_nodes,
            "edge_ids": component_edges,
            "size": len(component_nodes),
        })

    return {
        "cycle_count": len(summaries),
        "components": summaries,
    }