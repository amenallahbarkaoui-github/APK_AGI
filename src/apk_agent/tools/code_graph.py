"""Code Graph — NetworkX-based call graph for APK analysis.

Builds a persistent directed graph of every class → method → call relationship
from the smali bytecode. Once built (after decompilation), queries are instant
instead of re-scanning thousands of files each time.

Graph storage: {project.outputs_dir}/call_graph.pickle
Index storage:  {project.outputs_dir}/code_index.json

Node types:
  - class:  Lcom/example/Foo;
  - method: Lcom/example/Foo;->bar

Edge types:
  - "calls":    method A → method B  (A invokes B)
  - "contains": class → method       (class owns the method)
  - "extends":  class → super_class  (inheritance)
  - "implements": class → interface  (interface impl)
"""

from __future__ import annotations

import json
import os
import pickle
import re
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

try:
    import networkx as nx
except ImportError:
    nx = None  # Will check at runtime

# Thread pool for parallel smali parsing
_GRAPH_POOL = ThreadPoolExecutor(max_workers=8)


# ---------------------------------------------------------------------------
# Regex patterns for smali parsing
# ---------------------------------------------------------------------------
_RE_CLASS = re.compile(r"^\.class\s+.*\s+(L[\w/$]+;)", re.MULTILINE)
_RE_SUPER = re.compile(r"^\.super\s+(L[\w/$]+;)", re.MULTILINE)
_RE_INTERFACE = re.compile(r"^\.implements\s+(L[\w/$]+;)", re.MULTILINE)
_RE_METHOD_START = re.compile(
    r"^\.method\s+(.*?)([\w<>$]+)\((.*?)\)(.*?)$", re.MULTILINE
)
_RE_INVOKE = re.compile(r"(L[\w/$]+;)->([\w<>$]+)\(")
_RE_FIELD = re.compile(r"^\.field\s+(.*)", re.MULTILINE)
_RE_STRING = re.compile(r'const-string(?:/jumbo)?\s+\w+,\s*"(.*?)"')


def _ensure_networkx():
    if nx is None:
        raise ImportError(
            "networkx is required for code graph features. "
            "Install it: pip install networkx"
        )


# ---------------------------------------------------------------------------
# Build graph from smali directories
# ---------------------------------------------------------------------------

def build_code_graph(
    smali_dirs: list[Path],
    progress_callback=None,
) -> "nx.DiGraph":
    """Parse all smali files and build a full code graph.

    Uses ThreadPoolExecutor for parallel file I/O and parsing (8 workers).
    File parsing produces node/edge lists that are merged into the graph
    under a lock to maintain thread safety.

    Args:
        smali_dirs: List of smali directories (smali/, smali_classes2/, etc.)
        progress_callback: Optional fn(percent, message) for progress updates.

    Returns:
        NetworkX DiGraph with class and method nodes + call edges.
    """
    _ensure_networkx()

    G = nx.DiGraph()
    total_files = 0

    # Normalize to Path objects
    smali_dirs = [Path(sd) for sd in smali_dirs]

    # Collect all smali file paths
    file_tasks: list[tuple[Path, Path]] = []  # (fpath, base_dir)
    for sd in smali_dirs:
        if not sd.is_dir():
            continue
        for root, _dirs, files in os.walk(sd):
            for fname in files:
                if fname.endswith(".smali"):
                    file_tasks.append((Path(root) / fname, sd))

    total_files = len(file_tasks)
    if total_files == 0:
        return G

    # Parse files in parallel — each returns (nodes, edges, class_attrs)
    graph_lock = Lock()
    files_done = [0]  # mutable counter for closure

    def _parse_worker(args: tuple[Path, Path]):
        fpath, base_dir = args
        return _parse_smali_to_data(fpath, base_dir)

    futures = {_GRAPH_POOL.submit(_parse_worker, task): task for task in file_tasks}
    for future in as_completed(futures):
        try:
            data = future.result(timeout=60)
            if data is None:
                continue
            nodes, edges, class_attrs = data

            with graph_lock:
                for node_id, attrs in nodes:
                    G.add_node(node_id, **attrs)
                for src, dst, attrs in edges:
                    G.add_edge(src, dst, **attrs)
                for node_id, key, val in class_attrs:
                    if node_id in G.nodes:
                        G.nodes[node_id][key] = val

                files_done[0] += 1
                if progress_callback and files_done[0] % 50 == 0:
                    pct = files_done[0] / total_files * 100
                    progress_callback(
                        pct,
                        f"Building graph: {files_done[0]}/{total_files} files",
                    )
        except Exception:
            continue

    # Store metadata
    G.graph["total_files"] = total_files
    G.graph["total_classes"] = sum(
        1 for _, d in G.nodes(data=True) if d.get("type") == "class"
    )
    G.graph["total_methods"] = sum(
        1 for _, d in G.nodes(data=True) if d.get("type") == "method"
    )
    G.graph["total_edges"] = G.number_of_edges()
    G.graph["built_at"] = time.time()

    return G


def _parse_smali_to_data(
    fpath: Path, base_dir: Path
) -> tuple[list, list, list] | None:
    """Parse a single smali file and return raw node/edge data (thread-safe).

    Returns:
        (nodes, edges, class_attrs) or None if unparseable.
        nodes: list of (node_id, attrs_dict)
        edges: list of (src, dst, attrs_dict)
        class_attrs: list of (node_id, key, value)
    """
    try:
        text = fpath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    rel_path = str(fpath.relative_to(base_dir))

    class_match = _RE_CLASS.search(text)
    if not class_match:
        return None

    class_name = class_match.group(1)

    nodes: list[tuple[str, dict]] = []
    edges: list[tuple[str, str, dict]] = []
    class_attrs: list[tuple[str, str, object]] = []

    # Class node
    nodes.append((class_name, {"type": "class", "file": rel_path}))

    # Inheritance
    super_match = _RE_SUPER.search(text)
    if super_match:
        super_class = super_match.group(1)
        edges.append((class_name, super_class, {"relation": "extends"}))

    # Interfaces
    for iface_match in _RE_INTERFACE.finditer(text):
        iface = iface_match.group(1)
        edges.append((class_name, iface, {"relation": "implements"}))

    # Parse methods and calls
    lines = text.splitlines()
    current_method = None
    current_method_full = None

    for i, line in enumerate(lines):
        stripped = line.strip()

        if stripped.startswith(".method"):
            m = re.search(r"([\w<>$]+)\(", stripped)
            if m:
                current_method = m.group(1)
                current_method_full = f"{class_name}->{current_method}"
                method_access = stripped.split(current_method)[0].replace(".method", "").strip()
                nodes.append((
                    current_method_full,
                    {
                        "type": "method",
                        "access": method_access,
                        "file": rel_path,
                        "line": i + 1,
                        "class_name": class_name,
                        "short_name": current_method,
                    },
                ))
                edges.append((class_name, current_method_full, {"relation": "contains"}))

        elif stripped == ".end method":
            current_method = None
            current_method_full = None

        elif stripped.startswith("invoke-") and current_method_full:
            m = _RE_INVOKE.search(stripped)
            if m:
                callee_class = m.group(1)
                callee_method = m.group(2)
                callee_full = f"{callee_class}->{callee_method}"
                nodes.append((callee_full, {"type": "method", "class_name": callee_class, "short_name": callee_method}))
                nodes.append((callee_class, {"type": "class"}))
                edges.append((current_method_full, callee_full, {"relation": "calls", "file": rel_path, "line": i + 1}))

    # String constants
    strings = _RE_STRING.findall(text)[:50]
    if strings:
        class_attrs.append((class_name, "strings", strings))

    # Fields
    fields = _RE_FIELD.findall(text)[:30]
    if fields:
        class_attrs.append((class_name, "fields", [f.strip()[:100] for f in fields]))

    return nodes, edges, class_attrs


# ---------------------------------------------------------------------------
# Persistence — save / load graph
# ---------------------------------------------------------------------------

def save_graph(G: "nx.DiGraph", output_path: Path) -> dict:
    """Save graph to pickle file. Returns stats."""
    _ensure_networkx()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        pickle.dump(G, f, protocol=pickle.HIGHEST_PROTOCOL)
    size_kb = output_path.stat().st_size / 1024
    return {
        "success": True,
        "path": str(output_path),
        "size_kb": round(size_kb, 1),
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "classes": G.graph.get("total_classes", 0),
        "methods": G.graph.get("total_methods", 0),
    }


def load_graph(graph_path: Path) -> "nx.DiGraph | None":
    """Load graph from pickle. Returns None if not found."""
    _ensure_networkx()
    if not graph_path.is_file():
        return None
    with open(graph_path, "rb") as f:
        return pickle.load(f)


# ---------------------------------------------------------------------------
# Query functions — these are what the agent tools call
# ---------------------------------------------------------------------------

def query_callers(G: "nx.DiGraph", method_name: str, depth: int = 3) -> dict:
    """Find all callers of a method (reverse call chain).

    Unlike trace_call_chain in deep_analyzer.py, this is INSTANT because
    the graph is pre-built. No file scanning needed.
    """
    _ensure_networkx()

    # Find matching nodes (partial match)
    targets = [
        n for n, d in G.nodes(data=True)
        if d.get("type") == "method" and method_name in n
    ]

    if not targets:
        return {
            "success": True,
            "method": method_name,
            "found": False,
            "hint": "Method not in graph. Try a different name or rebuild the graph.",
        }

    all_chains = []
    visited = set()

    for target in targets[:5]:  # Limit to 5 matches
        _trace_callers_recursive(G, target, depth, 0, all_chains, visited)

    return {
        "success": True,
        "method": method_name,
        "found": True,
        "matched_nodes": targets[:5],
        "total_callers": len(all_chains),
        "call_chains": all_chains[:100],
    }


def _trace_callers_recursive(G, node, max_depth, current_depth, results, visited):
    """Recursively find callers via incoming 'calls' edges."""
    if current_depth >= max_depth or node in visited:
        return
    visited.add(node)

    for pred in G.predecessors(node):
        edge_data = G.edges[pred, node]
        if edge_data.get("relation") == "calls":
            pred_data = G.nodes.get(pred, {})
            results.append({
                "depth": current_depth,
                "target": node,
                "caller": pred,
                "caller_file": pred_data.get("file", ""),
                "caller_line": edge_data.get("line", 0),
            })
            _trace_callers_recursive(G, pred, max_depth, current_depth + 1, results, visited)


def query_callees(G: "nx.DiGraph", method_name: str, depth: int = 2) -> dict:
    """Find all methods called BY a method (forward call chain)."""
    _ensure_networkx()

    targets = [
        n for n, d in G.nodes(data=True)
        if d.get("type") == "method" and method_name in n
    ]

    if not targets:
        return {"success": True, "method": method_name, "found": False}

    all_callees = []
    visited = set()

    for target in targets[:5]:
        _trace_callees_recursive(G, target, depth, 0, all_callees, visited)

    return {
        "success": True,
        "method": method_name,
        "found": True,
        "matched_nodes": targets[:5],
        "total_callees": len(all_callees),
        "callees": all_callees[:100],
    }


def _trace_callees_recursive(G, node, max_depth, current_depth, results, visited):
    """Recursively find callees via outgoing 'calls' edges."""
    if current_depth >= max_depth or node in visited:
        return
    visited.add(node)

    for succ in G.successors(node):
        edge_data = G.edges[node, succ]
        if edge_data.get("relation") == "calls":
            succ_data = G.nodes.get(succ, {})
            results.append({
                "depth": current_depth,
                "callee": succ,
                "callee_file": succ_data.get("file", ""),
                "callee_class": succ_data.get("class_name", ""),
            })
            _trace_callees_recursive(G, succ, max_depth, current_depth + 1, results, visited)


def query_class_info(G: "nx.DiGraph", class_name: str) -> dict:
    """Get full info about a class — methods, fields, inheritance, callers."""
    _ensure_networkx()

    # Partial match
    matches = [
        n for n, d in G.nodes(data=True)
        if d.get("type") == "class" and class_name in n
    ]

    if not matches:
        return {"success": True, "class": class_name, "found": False}

    results = []
    for cls in matches[:5]:
        data = G.nodes[cls]
        methods = []
        for succ in G.successors(cls):
            edge = G.edges[cls, succ]
            if edge.get("relation") == "contains":
                succ_data = G.nodes.get(succ, {})
                # Count how many call this method
                caller_count = sum(
                    1 for p in G.predecessors(succ)
                    if G.edges[p, succ].get("relation") == "calls"
                )
                methods.append({
                    "name": succ_data.get("short_name", succ),
                    "full_name": succ,
                    "access": succ_data.get("access", ""),
                    "file": succ_data.get("file", ""),
                    "line": succ_data.get("line", 0),
                    "caller_count": caller_count,
                })

        # Get inheritance
        extends = []
        implements = []
        for succ in G.successors(cls):
            edge = G.edges[cls, succ]
            if edge.get("relation") == "extends":
                extends.append(succ)
            elif edge.get("relation") == "implements":
                implements.append(succ)

        # Get subclasses
        subclasses = []
        for pred in G.predecessors(cls):
            edge = G.edges[pred, cls]
            if edge.get("relation") == "extends":
                subclasses.append(pred)

        results.append({
            "class": cls,
            "file": data.get("file", ""),
            "extends": extends,
            "implements": implements,
            "subclasses": subclasses,
            "strings": data.get("strings", [])[:20],
            "fields": data.get("fields", [])[:20],
            "methods": sorted(methods, key=lambda m: -m["caller_count"])[:30],
        })

    return {"success": True, "found": True, "classes": results}


def query_path(G: "nx.DiGraph", source: str, target: str) -> dict:
    """Find the shortest call path between two methods."""
    _ensure_networkx()

    # Find matching nodes
    src_nodes = [n for n in G.nodes if source in n and G.nodes[n].get("type") == "method"]
    tgt_nodes = [n for n in G.nodes if target in n and G.nodes[n].get("type") == "method"]

    if not src_nodes:
        return {"success": True, "found": False, "error": f"Source '{source}' not found"}
    if not tgt_nodes:
        return {"success": True, "found": False, "error": f"Target '{target}' not found"}

    best_path = None
    for s in src_nodes[:3]:
        for t in tgt_nodes[:3]:
            try:
                path = nx.shortest_path(G, s, t)
                if best_path is None or len(path) < len(best_path):
                    best_path = path
            except nx.NetworkXNoPath:
                continue

    if not best_path:
        return {
            "success": True,
            "found": False,
            "error": f"No call path between '{source}' and '{target}'",
        }

    # Build detailed path
    steps = []
    for i, node in enumerate(best_path):
        node_data = G.nodes.get(node, {})
        step = {
            "step": i,
            "node": node,
            "type": node_data.get("type", "unknown"),
            "file": node_data.get("file", ""),
        }
        if i > 0:
            edge = G.edges.get((best_path[i - 1], node), {})
            step["relation"] = edge.get("relation", "unknown")
        steps.append(step)

    return {
        "success": True,
        "found": True,
        "path_length": len(best_path),
        "path": steps,
    }


def get_graph_stats(G: "nx.DiGraph") -> dict:
    """Get summary statistics about the code graph."""
    _ensure_networkx()

    class_count = sum(1 for _, d in G.nodes(data=True) if d.get("type") == "class")
    method_count = sum(1 for _, d in G.nodes(data=True) if d.get("type") == "method")
    call_edges = sum(1 for _, _, d in G.edges(data=True) if d.get("relation") == "calls")
    extends_edges = sum(1 for _, _, d in G.edges(data=True) if d.get("relation") == "extends")
    implements_edges = sum(1 for _, _, d in G.edges(data=True) if d.get("relation") == "implements")

    # Find most-called methods (highest in-degree with 'calls' relation)
    call_in_degree = defaultdict(int)
    for _, target, d in G.edges(data=True):
        if d.get("relation") == "calls":
            call_in_degree[target] += 1

    hotspots = sorted(call_in_degree.items(), key=lambda x: -x[1])[:20]

    return {
        "success": True,
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "classes": class_count,
        "methods": method_count,
        "call_edges": call_edges,
        "inheritance_edges": extends_edges,
        "interface_edges": implements_edges,
        "most_called_methods": [
            {"method": m, "call_count": c} for m, c in hotspots
        ],
        "built_at": G.graph.get("built_at", 0),
        "files_parsed": G.graph.get("total_files", 0),
    }


def find_security_methods(G: "nx.DiGraph") -> dict:
    """Find methods related to security based on name patterns.

    Returns grouped results: ssl, root_detection, crypto, anti_debug, etc.
    """
    _ensure_networkx()

    patterns = {
        "ssl_pinning": re.compile(
            r"(checkServerTrusted|CertificatePinner|HostnameVerifier|"
            r"X509TrustManager|SSLSocketFactory|PinningTrustManager)",
            re.IGNORECASE,
        ),
        "root_detection": re.compile(
            r"(isRooted|rootCheck|RootBeer|detectRoot|suBinary|"
            r"checkForSu|SafetyNet|PlayIntegrity)",
            re.IGNORECASE,
        ),
        "crypto": re.compile(
            r"(Cipher|SecretKey|AES|encrypt|decrypt|"
            r"MessageDigest|HMAC|KeyGenerator|IvParameterSpec)",
            re.IGNORECASE,
        ),
        "anti_debug": re.compile(
            r"(isDebuggerConnected|ptrace|TracerPid|"
            r"Debug;->|isDebuggable|debugDetect)",
            re.IGNORECASE,
        ),
        "anti_tamper": re.compile(
            r"(getPackageInfo|GET_SIGNATURES|signature|checkSignature|"
            r"PackageManager|verifySignature|integrity)",
            re.IGNORECASE,
        ),
        "dynamic_loading": re.compile(
            r"(DexClassLoader|PathClassLoader|loadClass|"
            r"Class\.forName|InMemoryDex|loadLibrary)",
            re.IGNORECASE,
        ),
        "billing_purchase": re.compile(
            r"(BillingClient|queryPurchases|launchBillingFlow|"
            r"acknowledgePurchase|PurchasesUpdatedListener|"
            r"onPurchasesUpdated|SkuDetails|ProductDetails|"
            r"InAppBillingService|isPurchased|isPremium|"
            r"isSubscribed|getSubscription|verifyPurchase|"
            r"checkLicense|LicenseChecker|allowAccess)",
            re.IGNORECASE,
        ),
    }

    results = {}
    for category, pattern in patterns.items():
        hits = []
        for node, data in G.nodes(data=True):
            if data.get("type") == "method" and pattern.search(node):
                # Count callers
                caller_count = sum(
                    1 for p in G.predecessors(node)
                    if G.edges[p, node].get("relation") == "calls"
                )
                hits.append({
                    "method": node,
                    "class": data.get("class_name", ""),
                    "file": data.get("file", ""),
                    "line": data.get("line", 0),
                    "caller_count": caller_count,
                })
        if hits:
            results[category] = sorted(hits, key=lambda h: -h["caller_count"])

    return {
        "success": True,
        "categories_found": len(results),
        "methods": results,
    }
