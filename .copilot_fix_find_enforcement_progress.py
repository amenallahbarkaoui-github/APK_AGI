from pathlib import Path

ROOT = Path(r"c:\Users\Amenallah\Desktop\APK AGI")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def replace_exact(relative_path: str, old: str, new: str) -> None:
    path = ROOT / relative_path
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"Snippet not found in {relative_path}:\n{old[:200]}")
    write_text(path, text.replace(old, new, 1))


def append_text(relative_path: str, addition: str) -> None:
    path = ROOT / relative_path
    text = path.read_text(encoding="utf-8")
    if addition in text:
        return
    write_text(path, text + addition)


replace_exact(
    "src/apk_agent/tools/semantic_cache.py",
    '''def get_cached_architecture_context(index, *, focus_terms: set[str] | None = None) -> dict[str, Any]:
    if index is None:
        return {
            "role_classes": {role: set() for role in _ARCHITECTURE_ROLES},
            "role_scores": {},
            "state_fields": set(),
            "state_field_semantics": {},
            "state_field_scores": {},
            "writer_methods": set(),
            "reader_methods": set(),
            "guard_methods": set(),
            "guard_method_scores": {},
            "overwrite_methods": set(),
            "dynamic_boundary_methods": set(),
            "revalidation_classes": set(),
            "summary": {},
        }

    normalized_focus_terms = tuple(sorted(term for term in (focus_terms or set()) if term))
    key = (_index_signature(index), normalized_focus_terms)
    cache = _slot_cache("architecture_context_cache")
    if key in cache:
        return cache[key]

    focus_hint = ",".join(normalized_focus_terms)
    architecture = get_cached_semantic_architecture(index, focus_hint=focus_hint, max_per_role=20)
    hidden_state = get_cached_hidden_state_model(index, focus_hint=focus_hint, max_candidates=50)
    guard_surface = get_cached_guard_surface_profile(index, focus_hint=focus_hint, max_clusters=50)

    role_classes: dict[str, set[str]] = {role: set() for role in _ARCHITECTURE_ROLES}
    role_scores: dict[str, dict[str, float]] = {}
    for role in _ARCHITECTURE_ROLES:
        for item in architecture.get("architecture_layers", {}).get(role, []):
            class_name = item.get("class", "")
            if not class_name:
                continue
            role_classes[role].add(class_name)
            role_scores.setdefault(class_name, {})[role] = float(item.get("score", 0))

    state_fields: set[str] = set()
    state_field_semantics: dict[str, str] = {}
    state_field_scores: dict[str, float] = {}
    for item in hidden_state.get("candidate_state_fields", []):
        field_ref = f"{item.get('class', '')}->{item.get('field', '')}"
        if not field_ref.endswith("->"):
            state_fields.add(field_ref)
            state_field_semantics[field_ref] = str(item.get("semantic_guess", "state_value"))
            state_field_scores[field_ref] = float(item.get("score", 0))

    writer_methods = {item.get("writer", "") for item in hidden_state.get("writer_chains", []) if item.get("writer")}
    reader_methods = {item.get("reader", "") for item in hidden_state.get("reader_chains", []) if item.get("reader")}

    guard_methods: set[str] = set()
    guard_method_scores: dict[str, int] = {}
    for item in guard_surface.get("guard_clusters", []):
        method_sig = item.get("method", "")
        if method_sig:
            guard_methods.add(method_sig)
            guard_method_scores[method_sig] = int(item.get("severity_score", 0))

    overwrite_methods = {item.get("method", "") for item in guard_surface.get("overwrite_points", []) if item.get("method")}
    dynamic_boundary_methods = {item.get("method", "") for item in guard_surface.get("native_or_dynamic_boundaries", []) if item.get("method")}
    revalidation_classes = {item.get("class", "") for item in guard_surface.get("revalidation_loops", []) if item.get("class")}

    context = {
        "role_classes": role_classes,
        "role_scores": role_scores,
        "state_fields": state_fields,
        "state_field_semantics": state_field_semantics,
        "state_field_scores": state_field_scores,
        "writer_methods": writer_methods,
        "reader_methods": reader_methods,
        "guard_methods": guard_methods,
        "guard_method_scores": guard_method_scores,
        "overwrite_methods": overwrite_methods,
        "dynamic_boundary_methods": dynamic_boundary_methods,
        "revalidation_classes": revalidation_classes,
        "summary": {
            "focus_terms": list(normalized_focus_terms),
            "state_models": len(role_classes["state_models"]),
            "network_layer": len(role_classes["network_layer"]),
            "serialization_layer": len(role_classes["serialization_layer"]),
            "ui_gate_controllers": len(role_classes["ui_gate_controllers"]),
            "guard_methods": len(guard_methods),
            "recovered_state_fields": len(state_fields),
            "revalidation_classes": len(revalidation_classes),
        },
    }
    cache[key] = context
    return context
''',
    '''def get_cached_architecture_context(index, *, focus_terms: set[str] | None = None, progress_callback=None) -> dict[str, Any]:
    if index is None:
        return {
            "role_classes": {role: set() for role in _ARCHITECTURE_ROLES},
            "role_scores": {},
            "state_fields": set(),
            "state_field_semantics": {},
            "state_field_scores": {},
            "writer_methods": set(),
            "reader_methods": set(),
            "guard_methods": set(),
            "guard_method_scores": {},
            "overwrite_methods": set(),
            "dynamic_boundary_methods": set(),
            "revalidation_classes": set(),
            "summary": {},
        }

    def _emit_progress(pct: float, detail: str) -> None:
        if progress_callback is not None:
            progress_callback(pct, detail)

    normalized_focus_terms = tuple(sorted(term for term in (focus_terms or set()) if term))
    key = (_index_signature(index), normalized_focus_terms)
    cache = _slot_cache("architecture_context_cache")
    if key in cache:
        summary = cache[key].get("summary", {}) if isinstance(cache[key], dict) else {}
        _emit_progress(
            100,
            "Using cached architecture context: "
            f"{summary.get('recovered_state_fields', 0)} state fields, "
            f"{summary.get('guard_methods', 0)} guard methods",
        )
        return cache[key]

    focus_hint = ",".join(normalized_focus_terms)
    if normalized_focus_terms:
        _emit_progress(4, f"Recovering semantic architecture layers for {len(normalized_focus_terms)} focus terms")
    else:
        _emit_progress(4, "Recovering semantic architecture layers")
    architecture = get_cached_semantic_architecture(index, focus_hint=focus_hint, max_per_role=20)
    architecture_layers = architecture.get("architecture_layers", {}) if isinstance(architecture, dict) else {}
    ranked_role_hits = sum(len(items) for items in architecture_layers.values() if isinstance(items, list))
    _emit_progress(28, f"Semantic architecture ready: {ranked_role_hits} ranked role hits")

    _emit_progress(30, "Recovering hidden-state model")
    if progress_callback is not None:
        hidden_state = get_cached_hidden_state_model(
            index,
            focus_hint=focus_hint,
            max_candidates=50,
            progress_callback=lambda pct, detail: _emit_progress(30 + (pct * 0.42), detail),
        )
    else:
        hidden_state = get_cached_hidden_state_model(index, focus_hint=focus_hint, max_candidates=50)
    hidden_summary = hidden_state.get("summary", {}) if isinstance(hidden_state, dict) else {}
    _emit_progress(74, f"Hidden-state recovery ready: {hidden_summary.get('field_candidates', 0)} field candidates")

    _emit_progress(76, "Profiling guard and revalidation surfaces")
    guard_surface = get_cached_guard_surface_profile(index, focus_hint=focus_hint, max_clusters=50)
    guard_summary = guard_surface.get("summary", {}) if isinstance(guard_surface, dict) else {}
    _emit_progress(
        92,
        "Merging architecture context: "
        f"{guard_summary.get('guard_clusters', 0)} guard clusters, "
        f"{guard_summary.get('revalidation_loops', 0)} revalidation loops",
    )

    role_classes: dict[str, set[str]] = {role: set() for role in _ARCHITECTURE_ROLES}
    role_scores: dict[str, dict[str, float]] = {}
    for role in _ARCHITECTURE_ROLES:
        for item in architecture.get("architecture_layers", {}).get(role, []):
            class_name = item.get("class", "")
            if not class_name:
                continue
            role_classes[role].add(class_name)
            role_scores.setdefault(class_name, {})[role] = float(item.get("score", 0))

    state_fields: set[str] = set()
    state_field_semantics: dict[str, str] = {}
    state_field_scores: dict[str, float] = {}
    for item in hidden_state.get("candidate_state_fields", []):
        field_ref = f"{item.get('class', '')}->{item.get('field', '')}"
        if not field_ref.endswith("->"):
            state_fields.add(field_ref)
            state_field_semantics[field_ref] = str(item.get("semantic_guess", "state_value"))
            state_field_scores[field_ref] = float(item.get("score", 0))

    writer_methods = {item.get("writer", "") for item in hidden_state.get("writer_chains", []) if item.get("writer")}
    reader_methods = {item.get("reader", "") for item in hidden_state.get("reader_chains", []) if item.get("reader")}

    guard_methods: set[str] = set()
    guard_method_scores: dict[str, int] = {}
    for item in guard_surface.get("guard_clusters", []):
        method_sig = item.get("method", "")
        if method_sig:
            guard_methods.add(method_sig)
            guard_method_scores[method_sig] = int(item.get("severity_score", 0))

    overwrite_methods = {item.get("method", "") for item in guard_surface.get("overwrite_points", []) if item.get("method")}
    dynamic_boundary_methods = {item.get("method", "") for item in guard_surface.get("native_or_dynamic_boundaries", []) if item.get("method")}
    revalidation_classes = {item.get("class", "") for item in guard_surface.get("revalidation_loops", []) if item.get("class")}

    context = {
        "role_classes": role_classes,
        "role_scores": role_scores,
        "state_fields": state_fields,
        "state_field_semantics": state_field_semantics,
        "state_field_scores": state_field_scores,
        "writer_methods": writer_methods,
        "reader_methods": reader_methods,
        "guard_methods": guard_methods,
        "guard_method_scores": guard_method_scores,
        "overwrite_methods": overwrite_methods,
        "dynamic_boundary_methods": dynamic_boundary_methods,
        "revalidation_classes": revalidation_classes,
        "summary": {
            "focus_terms": list(normalized_focus_terms),
            "state_models": len(role_classes["state_models"]),
            "network_layer": len(role_classes["network_layer"]),
            "serialization_layer": len(role_classes["serialization_layer"]),
            "ui_gate_controllers": len(role_classes["ui_gate_controllers"]),
            "guard_methods": len(guard_methods),
            "recovered_state_fields": len(state_fields),
            "revalidation_classes": len(revalidation_classes),
        },
    }
    cache[key] = context
    _emit_progress(
        100,
        "Architecture context ready: "
        f"{len(state_fields)} state fields, {len(guard_methods)} guard methods, "
        f"{len(revalidation_classes)} revalidation classes",
    )
    return context
''',
)

replace_exact(
    "src/apk_agent/tools/semantic_graph.py",
    '''def find_enforcement_surfaces(
    index: "SmaliIndex",
    feature: str,
    *,
    graph=None,
    extra_keywords: str = "",
    max_results: int = 25,
) -> dict[str, Any]:
    """Find likely enforcement methods using architecture/state/revalidation context.

    `feature` and `extra_keywords` are treated as optional focus hints only.
    They may help narrow or tie-break results, but they do not gate discovery.
    The ranking is architecture-first so it still works when business strings and
    method/class names are obfuscated.
    """
    focus_terms = _focus_terms(feature, extra_keywords)
    architecture_context = _build_architecture_context(index, focus_terms)

    candidates: list[dict[str, Any]] = []
    role_counts: Counter[str] = Counter()

    for method in index.methods.values():
        class_name = method.full_signature.split("->", 1)[0] if "->" in method.full_signature else ""
        cls = index.get_class(class_name)
        file_path = cls.file_path if cls else ""

        field_accesses = [instr.target_field for instr in method.instructions if instr.is_field_access and instr.target_field]
        branch_count = sum(1 for instr in method.instructions if instr.is_branch)
        field_count = sum(1 for instr in method.instructions if instr.is_field_access)
        field_write_count = _field_write_count(method)
        api_categories = _classify_api_calls(method.api_calls)

        graph_sig = _graph_method_signature(method.full_signature)
        direct_callers = _direct_callers(graph, graph_sig) if graph is not None else []
        direct_callees = _direct_callees(graph, graph_sig) if graph is not None else []
        graph_role_contexts = _graph_role_contexts(direct_callers, direct_callees, architecture_context)
        structure = _method_architecture_profile(
            method,
            class_name,
            file_path,
            field_accesses,
            field_write_count,
            api_categories,
            architecture_context,
        )
        focus_hits = _focus_hits(
            [
                class_name,
                file_path,
                cls.source_file if cls else "",
                method.name,
                method.full_signature,
                *method.api_calls,
                *method.string_constants,
                *field_accesses,
            ],
            focus_terms,
        )

        if not _is_structural_enforcement_candidate(
            method,
            structure,
            branch_count,
            field_count,
            field_write_count,
            direct_callers,
            direct_callees,
        ):
            continue

        surface_role = _surface_role(method, branch_count, field_write_count, api_categories, structure, graph_role_contexts)
        third_party_path = bool(file_path and _is_third_party_path(file_path))
        score, reasons = _score_method(
            method,
            branch_count,
            field_count,
            field_write_count,
            api_categories,
            direct_callers,
            direct_callees,
            graph_role_contexts,
            third_party_path,
            surface_role,
            structure,
            focus_hits,
        )

        if score < 24:
            continue

        role_counts[surface_role] += 1
        candidates.append({
            "score": score,
            "reasons": reasons,
            "surface_role": surface_role,
            "class": class_name,
            "file": file_path,
            "method": method.full_signature,
            "return_type": method.return_type,
            "category": method.category,
            "focus_matches": focus_hits[:8],
            "api_categories": api_categories,
            "caller_count": len(direct_callers),
            "callee_count": len(direct_callees),
            "graph_role_contexts": graph_role_contexts,
            "owner_roles": structure["owner_roles"],
            "architecture_signals": structure["signals"][:10],
            "state_field_hits": structure["state_field_hits"][:8],
            "state_field_semantics": structure["state_field_semantics"][:8],
            "direct_callers": direct_callers[:8],
            "direct_callees": direct_callees[:8],
            "branch_count": branch_count,
            "field_access_count": field_count,
            "field_write_count": field_write_count,
            "guard_cluster_match": structure["guard_cluster_match"],
            "revalidation_loop_owner": structure["revalidation_loop_owner"],
            "third_party_path": third_party_path,
        })

    candidates.sort(key=lambda item: (-item["score"], item["method"]))
    top = candidates[:max_results]
    return {
        "success": True,
        "feature": feature,
        "discovery_mode": "architecture_first",
        "focus_terms": sorted(focus_terms),
        "keywords": sorted(focus_terms),
        "architecture_summary": architecture_context["summary"],
        "total_candidates": len(candidates),
        "role_summary": dict(role_counts),
        "surfaces": top,
        "next_step": (
            "Start from the highest-scoring app-owned gate_method or revalidation_boundary. "
            "If architecture_signals mention recovered state fields or overwrite loops, patch the response/state-writer "
            "boundary first, then inspect downstream accessors with semantic_method_slice before rebuilding."
        ),
    }
''',
    '''def find_enforcement_surfaces(
    index: "SmaliIndex",
    feature: str,
    *,
    graph=None,
    extra_keywords: str = "",
    max_results: int = 25,
    progress_callback=None,
) -> dict[str, Any]:
    """Find likely enforcement methods using architecture/state/revalidation context.

    `feature` and `extra_keywords` are treated as optional focus hints only.
    They may help narrow or tie-break results, but they do not gate discovery.
    The ranking is architecture-first so it still works when business strings and
    method/class names are obfuscated.
    """
    def _emit_progress(pct: float, detail: str) -> None:
        if progress_callback is not None:
            progress_callback(pct, detail)

    focus_terms = _focus_terms(feature, extra_keywords)
    if focus_terms:
        _emit_progress(22, f"Preparing enforcement surface analysis for {len(focus_terms)} focus terms")
    else:
        _emit_progress(22, "Preparing enforcement surface analysis without keyword bias")
    architecture_context = _build_architecture_context(
        index,
        focus_terms,
        progress_callback=lambda pct, detail: _emit_progress(24 + (pct * 0.34), detail),
    )

    candidates: list[dict[str, Any]] = []
    role_counts: Counter[str] = Counter()
    total_methods = len(index.methods)
    scan_interval = max(1, total_methods // 18) if total_methods > 0 else 1

    _emit_progress(60, f"Scanning {total_methods} methods for enforcement candidates")

    for method_idx, method in enumerate(index.methods.values(), start=1):
        class_name = method.full_signature.split("->", 1)[0] if "->" in method.full_signature else ""
        cls = index.get_class(class_name)
        file_path = cls.file_path if cls else ""

        field_accesses = [instr.target_field for instr in method.instructions if instr.is_field_access and instr.target_field]
        branch_count = sum(1 for instr in method.instructions if instr.is_branch)
        field_count = sum(1 for instr in method.instructions if instr.is_field_access)
        field_write_count = _field_write_count(method)
        api_categories = _classify_api_calls(method.api_calls)

        structure = _method_architecture_profile(
            method,
            class_name,
            file_path,
            field_accesses,
            field_write_count,
            api_categories,
            architecture_context,
        )
        if not _has_prefilter_signal(method, structure, branch_count, field_count, field_write_count, api_categories):
            if method_idx == total_methods or method_idx % scan_interval == 0:
                scan_pct = 60 + (method_idx / max(total_methods, 1)) * 34
                _emit_progress(scan_pct, f"Method scan: {method_idx}/{total_methods} methods | {len(candidates)} candidates")
            continue

        graph_sig = _graph_method_signature(method.full_signature)
        direct_callers = _direct_callers(graph, graph_sig) if graph is not None else []
        direct_callees = _direct_callees(graph, graph_sig) if graph is not None else []
        graph_role_contexts = _graph_role_contexts(direct_callers, direct_callees, architecture_context)
        focus_hits = _focus_hits(
            [
                class_name,
                file_path,
                cls.source_file if cls else "",
                method.name,
                method.full_signature,
                *method.api_calls,
                *method.string_constants,
                *field_accesses,
            ],
            focus_terms,
        )

        if not _is_structural_enforcement_candidate(
            method,
            structure,
            branch_count,
            field_count,
            field_write_count,
            direct_callers,
            direct_callees,
        ):
            if method_idx == total_methods or method_idx % scan_interval == 0:
                scan_pct = 60 + (method_idx / max(total_methods, 1)) * 34
                _emit_progress(scan_pct, f"Method scan: {method_idx}/{total_methods} methods | {len(candidates)} candidates")
            continue

        surface_role = _surface_role(method, branch_count, field_write_count, api_categories, structure, graph_role_contexts)
        third_party_path = bool(file_path and _is_third_party_path(file_path))
        score, reasons = _score_method(
            method,
            branch_count,
            field_count,
            field_write_count,
            api_categories,
            direct_callers,
            direct_callees,
            graph_role_contexts,
            third_party_path,
            surface_role,
            structure,
            focus_hits,
        )

        if score < 24:
            if method_idx == total_methods or method_idx % scan_interval == 0:
                scan_pct = 60 + (method_idx / max(total_methods, 1)) * 34
                _emit_progress(scan_pct, f"Method scan: {method_idx}/{total_methods} methods | {len(candidates)} candidates")
            continue

        role_counts[surface_role] += 1
        candidates.append({
            "score": score,
            "reasons": reasons,
            "surface_role": surface_role,
            "class": class_name,
            "file": file_path,
            "method": method.full_signature,
            "return_type": method.return_type,
            "category": method.category,
            "focus_matches": focus_hits[:8],
            "api_categories": api_categories,
            "caller_count": len(direct_callers),
            "callee_count": len(direct_callees),
            "graph_role_contexts": graph_role_contexts,
            "owner_roles": structure["owner_roles"],
            "architecture_signals": structure["signals"][:10],
            "state_field_hits": structure["state_field_hits"][:8],
            "state_field_semantics": structure["state_field_semantics"][:8],
            "direct_callers": direct_callers[:8],
            "direct_callees": direct_callees[:8],
            "branch_count": branch_count,
            "field_access_count": field_count,
            "field_write_count": field_write_count,
            "guard_cluster_match": structure["guard_cluster_match"],
            "revalidation_loop_owner": structure["revalidation_loop_owner"],
            "third_party_path": third_party_path,
        })

        if method_idx == total_methods or method_idx % scan_interval == 0:
            scan_pct = 60 + (method_idx / max(total_methods, 1)) * 34
            _emit_progress(scan_pct, f"Method scan: {method_idx}/{total_methods} methods | {len(candidates)} candidates")

    _emit_progress(96, f"Ranking {len(candidates)} enforcement candidates")
    candidates.sort(key=lambda item: (-item["score"], item["method"]))
    top = candidates[:max_results]
    _emit_progress(100, f"Enforcement surface ranking complete: {len(candidates)} candidates, {len(top)} returned")
    return {
        "success": True,
        "feature": feature,
        "discovery_mode": "architecture_first",
        "focus_terms": sorted(focus_terms),
        "keywords": sorted(focus_terms),
        "architecture_summary": architecture_context["summary"],
        "total_candidates": len(candidates),
        "role_summary": dict(role_counts),
        "surfaces": top,
        "next_step": (
            "Start from the highest-scoring app-owned gate_method or revalidation_boundary. "
            "If architecture_signals mention recovered state fields or overwrite loops, patch the response/state-writer "
            "boundary first, then inspect downstream accessors with semantic_method_slice before rebuilding."
        ),
    }
''',
)

replace_exact(
    "src/apk_agent/tools/semantic_graph.py",
    '''def _build_architecture_context(index: "SmaliIndex", focus_terms: set[str]) -> dict[str, Any]:
    return get_cached_architecture_context(index, focus_terms=focus_terms)
''',
    '''def _build_architecture_context(index: "SmaliIndex", focus_terms: set[str], progress_callback=None) -> dict[str, Any]:
    return get_cached_architecture_context(index, focus_terms=focus_terms, progress_callback=progress_callback)
''',
)

replace_exact(
    "src/apk_agent/tools/semantic_graph.py",
    '''def _is_structural_enforcement_candidate(
    method: "SmaliMethod",
    structure: dict[str, Any],
    branch_count: int,
    field_count: int,
    field_write_count: int,
    direct_callers: list[dict[str, Any]],
    direct_callees: list[dict[str, Any]],
) -> bool:
    if structure["state_field_hits"] or structure["writer_chain_match"] or structure["reader_chain_match"]:
        return True
    if structure["guard_cluster_match"] or structure["revalidation_loop_owner"]:
        return True
    if structure["network_state_boundary"] or structure["state_store_boundary"]:
        return True
    if method.return_type in {"Z", "I"} and branch_count > 0 and (field_count > 0 or structure["state_model_owner"] or direct_callers):
        return True
    if field_write_count > 0 and (structure["entry_point_owner"] or structure["state_model_owner"] or direct_callees):
        return True
    if structure["dynamic_boundary_match"] and (branch_count > 0 or field_write_count > 0):
        return True
    return False
''',
    '''def _is_structural_enforcement_candidate(
    method: "SmaliMethod",
    structure: dict[str, Any],
    branch_count: int,
    field_count: int,
    field_write_count: int,
    direct_callers: list[dict[str, Any]],
    direct_callees: list[dict[str, Any]],
) -> bool:
    if structure["state_field_hits"] or structure["writer_chain_match"] or structure["reader_chain_match"]:
        return True
    if structure["guard_cluster_match"] or structure["revalidation_loop_owner"]:
        return True
    if structure["network_state_boundary"] or structure["state_store_boundary"]:
        return True
    if method.return_type in {"Z", "I"} and branch_count > 0 and (field_count > 0 or structure["state_model_owner"] or direct_callers):
        return True
    if field_write_count > 0 and (structure["entry_point_owner"] or structure["state_model_owner"] or direct_callees):
        return True
    if structure["dynamic_boundary_match"] and (branch_count > 0 or field_write_count > 0):
        return True
    return False


def _has_prefilter_signal(
    method: "SmaliMethod",
    structure: dict[str, Any],
    branch_count: int,
    field_count: int,
    field_write_count: int,
    api_categories: list[str],
) -> bool:
    if structure["owner_roles"]:
        return True
    if structure["state_field_hits"] or structure["writer_chain_match"] or structure["reader_chain_match"]:
        return True
    if structure["guard_cluster_match"] or structure["revalidation_loop_owner"]:
        return True
    if structure["network_state_boundary"] or structure["state_store_boundary"] or structure["dynamic_boundary_match"]:
        return True
    if method.return_type in {"Z", "I"} and (branch_count > 0 or field_count > 0):
        return True
    if field_write_count > 0:
        return True
    if api_categories:
        return True
    return False
''',
)

replace_exact(
    "src/apk_agent/agent/tools_def.py",
    '''        result = _find_surfaces(
            idx,
            feature,
            graph=graph,
            extra_keywords=extra_keywords,
            max_results=max_results,
        )
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]
''',
    '''        result = _find_surfaces(
            idx,
            feature,
            graph=graph,
            extra_keywords=extra_keywords,
            max_results=max_results,
            progress_callback=report_progress,
        )
        return json.dumps(result, ensure_ascii=False, indent=2)
''',
)

replace_exact(
    "src/apk_agent/ui.py",
    '''        self._running_tools: int = 0
        self._tool_progress_pct: float = 0.0
        self._tool_progress_detail: str = ""
        self._tools_completed_this_turn: int = 0
''',
    '''        self._running_tools: int = 0
        self._tool_progress_pct: float = 0.0
        self._tool_progress_detail: str = ""
        self._tool_progress_source: str = ""
        self._tools_completed_this_turn: int = 0
''',
)

replace_exact(
    "src/apk_agent/ui.py",
    '''            self._running_tools = 0
            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""
            self._tools_completed_this_turn = 0
''',
    '''            self._running_tools = 0
            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""
            self._tool_progress_source = ""
            self._tools_completed_this_turn = 0
''',
)

replace_exact(
    "src/apk_agent/ui.py",
    '''            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""
            self._agent_phase = ""
''',
    '''            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""
            self._tool_progress_source = ""
            self._agent_phase = ""
''',
)

replace_exact(
    "src/apk_agent/ui.py",
    '''            if not active_names:
                self._active_tool = ""
                self._active_tool_start = 0.0
                self._tool_progress_pct = 0.0
                self._tool_progress_detail = ""
                return
''',
    '''            if not active_names:
                self._active_tool = ""
                self._active_tool_start = 0.0
                self._tool_progress_pct = 0.0
                self._tool_progress_detail = ""
                self._tool_progress_source = ""
                return
''',
)

replace_exact(
    "src/apk_agent/ui.py",
    '''            if self._active_tool != label:
                self._active_tool_start = time.time()
                if len(active_names) > 1:
                    self._tool_progress_pct = 0.0
                    self._tool_progress_detail = ""
''',
    '''            if self._active_tool != label:
                self._active_tool_start = time.time()
                if len(active_names) > 1:
                    self._tool_progress_pct = 0.0
                    self._tool_progress_detail = ""
                    self._tool_progress_source = ""
''',
)

replace_exact(
    "src/apk_agent/ui.py",
    '''    def update_tool_progress(self, pct: float, detail: str = "") -> None:
        with self._lock:
            self._tool_progress_pct = pct
            if detail:
                self._tool_progress_detail = detail
''',
    '''    def update_tool_progress(self, pct: float, detail: str = "", source: str = "") -> None:
        with self._lock:
            self._tool_progress_pct = pct
            if detail:
                self._tool_progress_detail = detail
            if source:
                self._tool_progress_source = source
''',
)

replace_exact(
    "src/apk_agent/ui.py",
    '''            self._active_tool_start = 0.0
            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""
''',
    '''            self._active_tool_start = 0.0
            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""
            self._tool_progress_source = ""
''',
)

replace_exact(
    "src/apk_agent/ui.py",
    '''            if tt._tool_progress_detail and len(tt._active_tool_names) <= 1:
                detail = tt._tool_progress_detail
                if len(detail) > 40:
                    detail = detail[:37] + "..."
                tool_str += f" [dim]│ {detail}[/dim]"
            parts.append(tool_str)
''',
    '''            if tt._tool_progress_detail and len(tt._active_tool_names) <= 1:
                detail = tt._tool_progress_detail
                if len(detail) > 40:
                    detail = detail[:37] + "..."
                tool_str += f" [dim]│ {detail}[/dim]"
            elif len(tt._active_tool_names) > 1 and (tt._tool_progress_pct > 0 or tt._tool_progress_detail):
                active_detail_parts: list[str] = []
                if tt._tool_progress_source:
                    active_detail_parts.append(tt._tool_progress_source)
                if tt._tool_progress_pct > 0:
                    active_detail_parts.append(f"{tt._tool_progress_pct:.0f}%")
                if tt._tool_progress_detail:
                    active_detail_parts.append(tt._tool_progress_detail)
                if active_detail_parts:
                    active_detail = " | ".join(active_detail_parts)
                    if len(active_detail) > 72:
                        active_detail = active_detail[:69] + "..."
                    tool_str += f" [dim]│ active: {active_detail}[/dim]"
            parts.append(tool_str)
''',
)

replace_exact(
    "src/apk_agent/ui.py",
    '''        pct = task.progress_pct
        detail = task.metadata.get("detail", "")
        token_tracker.update_tool_progress(pct, detail)
''',
    '''        pct = task.progress_pct
        detail = task.metadata.get("detail", "")
        token_tracker.update_tool_progress(pct, detail, source=task.name)
''',
)

replace_exact(
    "test_heavy_tool_progress.py",
    '''from apk_agent.agent import tools_def
from apk_agent.tools import smali_ir
''',
    '''from apk_agent.agent import tools_def
from apk_agent.tools import smali_ir
from apk_agent.tools.semantic_graph import find_enforcement_surfaces as semantic_find_enforcement_surfaces
''',
)

append_text(
    "test_heavy_tool_progress.py",
    '''


def test_find_enforcement_surfaces_emits_staged_progress() -> None:
    index = smali_ir.SmaliIndex()

    gate_method = smali_ir.SmaliMethod(
        name="isPremiumUnlocked",
        signature="isPremiumUnlocked()Z",
        full_signature="Lcom/example/premium/PremiumGate;->isPremiumUnlocked()Z",
        return_type="Z",
        instructions=[
            smali_ir.SmaliInstruction(
                opcode="iget-boolean",
                is_field_access=True,
                target_field="Lcom/example/premium/PremiumState;->premium:Z",
            ),
            smali_ir.SmaliInstruction(opcode="if-eqz", is_branch=True, operands=["v0", ":cond_0"]),
        ],
        string_constants=["premium active"],
        category="general",
    )
    writer_method = smali_ir.SmaliMethod(
        name="applySubscriptionState",
        signature="applySubscriptionState(Ljava/lang/String;)V",
        full_signature="Lcom/example/premium/PremiumState;->applySubscriptionState(Ljava/lang/String;)V",
        return_type="V",
        instructions=[
            smali_ir.SmaliInstruction(
                opcode="iput-boolean",
                is_field_access=True,
                target_field="Lcom/example/premium/PremiumState;->premium:Z",
            ),
        ],
        api_calls=[
            "Lcom/android/billingclient/api/BillingClient;->queryPurchasesAsync",
            "Lcom/google/gson/Gson;->fromJson",
        ],
        category="network",
    )

    gate_class = smali_ir.SmaliClass(
        name="Lcom/example/premium/PremiumGate;",
        file_path="smali/com/example/premium/PremiumGate.smali",
        methods=[gate_method],
    )
    state_class = smali_ir.SmaliClass(
        name="Lcom/example/premium/PremiumState;",
        file_path="smali/com/example/premium/PremiumState.smali",
        fields=[smali_ir.SmaliField(name="premium", type="Z")],
        methods=[writer_method],
    )

    index.classes[gate_class.name] = gate_class
    index.classes[state_class.name] = state_class
    index.methods[gate_method.full_signature] = gate_method
    index.methods[writer_method.full_signature] = writer_method

    progress_updates: list[tuple[float, str]] = []

    result = semantic_find_enforcement_surfaces(
        index,
        "premium subscription",
        max_results=5,
        progress_callback=lambda pct, detail: progress_updates.append((pct, detail)),
    )

    assert result["success"] is True
    assert any("Preparing enforcement surface analysis" in detail for _, detail in progress_updates)
    assert any("Recovering semantic architecture layers" in detail for _, detail in progress_updates)
    assert any("Recovering hidden-state model" in detail for _, detail in progress_updates)
    assert any("Scanning 2 methods for enforcement candidates" in detail for _, detail in progress_updates)
    assert any("Method scan:" in detail for _, detail in progress_updates)
    assert progress_updates[-1][0] == 100
    assert "Enforcement surface ranking complete" in progress_updates[-1][1]



def test_find_enforcement_surfaces_wrapper_keeps_large_json_valid(monkeypatch) -> None:
    monkeypatch.setattr(tools_def, "_ensure_smali_index", lambda: smali_ir.SmaliIndex())
    monkeypatch.setattr(tools_def, "_ensure_graph", lambda: None)
    monkeypatch.setattr(tools_def, "_safe_call", lambda fn, name, _cache_hint=None: fn())

    def fake_find_surfaces(index, feature, **kwargs):
        assert kwargs.get("progress_callback") is not None
        surfaces = []
        for i in range(90):
            surfaces.append({
                "class": f"Lcom/example/C{i};",
                "file": f"smali/com/example/C{i}.smali",
                "method": f"Lcom/example/C{i};->m{i}()Z",
                "surface_role": "gate_method",
                "score": 100 - i,
                "reasons": ["x" * 320, "y" * 320],
                "third_party_path": False,
                "direct_callers": [],
                "direct_callees": [],
                "api_categories": ["billing", "network"],
            })
        return {
            "success": True,
            "feature": feature,
            "discovery_mode": "architecture_first",
            "focus_terms": ["premium"],
            "keywords": ["premium"],
            "architecture_summary": {"recovered_state_fields": 1},
            "total_candidates": len(surfaces),
            "role_summary": {"gate_method": len(surfaces)},
            "surfaces": surfaces,
        }

    monkeypatch.setattr("apk_agent.tools.semantic_graph.find_enforcement_surfaces", fake_find_surfaces)

    parsed = json.loads(tools_def.find_enforcement_surfaces.invoke({"feature": "premium", "max_results": 90}))

    assert parsed["success"] is True
    assert parsed["total_candidates"] == 90
    assert len(parsed["surfaces"]) == 90
''',
)

replace_exact(
    "test_ui_status.py",
    '''def test_live_status_bar_aggregates_parallel_tools(monkeypatch):
    tracker = ui.TokenTracker()
    monkeypatch.setattr(ui, "token_tracker", tracker)
    bar = ui.LiveStatusBar()

    tracker.start_turn()
    tracker.sync_running_tools(["map_feature_checks", "discover_entity_classes"])
    tracker.update_tool_progress(50, "halfway there")
    tracker.clear_active_tool("index_lookup_class(CustomerInfo)")
    tracker.clear_active_tool("index_lookup_class(Entitlement)")

    rendered = bar._render().plain

    assert "map_feature_checks" in rendered
    assert "discover_entity_classes" in rendered
    assert "50%" not in rendered
    assert "halfway there" not in rendered
    assert "index_lookup_class(CustomerInfo)" in rendered
    assert "index_lookup_class(Entitlement)" in rendered
''',
    '''def test_live_status_bar_aggregates_parallel_tools(monkeypatch):
    tracker = ui.TokenTracker()
    monkeypatch.setattr(ui, "token_tracker", tracker)
    bar = ui.LiveStatusBar()

    tracker.start_turn()
    tracker.sync_running_tools(["map_feature_checks", "discover_entity_classes"])
    tracker.update_tool_progress(50, "halfway there", source="discover_entity_classes")

    rendered = bar._render().plain

    assert "map_feature_checks" in rendered
    assert "discover_entity_classes" in rendered
    assert "50%" in rendered
    assert "halfway there" in rendered
    assert "active:" in rendered

    tracker.clear_active_tool("index_lookup_class(CustomerInfo)")
    tracker.clear_active_tool("index_lookup_class(Entitlement)")

    rendered_done = bar._render().plain

    assert "index_lookup_class(CustomerInfo)" in rendered_done
    assert "index_lookup_class(Entitlement)" in rendered_done
''',
)

print("patched")
