"""
Wraps evtx_parser.py / hive_parsers.py / hybrid_pipeline.py (unmodified,
under dfir_lib/) into a single run_analysis() call the job manager can
execute in the background.

Why sys.path instead of editing the scripts: hybrid_pipeline.py does
`from evtx_parser import parse_evtx_to_json` (absolute, not relative)
so you can keep dropping in updated versions of your own scripts
without having to rewrite their imports.
"""
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

DFIR_LIB_DIR = Path(__file__).resolve().parent / "dfir_lib"
if str(DFIR_LIB_DIR) not in sys.path:
    sys.path.insert(0, str(DFIR_LIB_DIR))

from evtx_parser import parse_evtx_to_json  # noqa: E402
from hive_parsers import parse_registry_hive  # noqa: E402
from hybrid_pipeline import (  # noqa: E402
    load_and_evaluate_sigma,
    build_enriched_tree,
    analyze_with_hybrid_ai,
)

from config import SIGMA_RULES_DIR, OLLAMA_MODEL, EVTX_EXTENSIONS
from job_manager import JobCancelled

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _severity_rank(level: str) -> int:
    return SEVERITY_ORDER.get((level or "").lower(), 5)


def _normalize_level(raw) -> str:
    if raw is None:
        return "unknown"
    return getattr(raw, "name", str(raw)).lower()


def _event_source_label(event: Dict[str, Any]) -> str:
    """Best-effort human label for what an event/alert is actually about."""
    return (
        event.get("Image")
        or event.get("ServiceName")
        or event.get("TargetObject")
        or event.get("TargetFilename")
        or event.get("QueryName")
        or event.get("DestinationIp")
        or "Unknown artifact"
    )


def _ingest_file(path: Path) -> List[Dict[str, Any]]:
    if path.suffix.lower() in EVTX_EXTENSIONS:
        return parse_evtx_to_json(str(path))
    return parse_registry_hive(str(path))


def run_analysis(
    job_id: str,
    file_paths: List[Path],
    update_stage: Callable[[str, str], None],
    is_cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """
    Runs the full pipeline for one job and returns a JSON-serializable dict:
      {
        total_events, event_category_counts,
        alerts_by_severity: {critical: [...], high: [...], ...},
        tree_text, ai_report
      }
    update_stage(job_id, stage_text) is called before each phase so the UI
    can show progress.

    is_cancelled() is checked at each stage boundary; if it returns True,
    JobCancelled is raised to unwind immediately. This is cooperative, not
    preemptive -- a stage already in flight (notably the Ollama HTTP call
    in analyze_with_hybrid_ai) will not be interrupted mid-request. It only
    stops the *next* stage from starting.
    """

    def check_cancel() -> None:
        if is_cancelled and is_cancelled():
            raise JobCancelled()

    update_stage(job_id, "Ingesting forensic telemetry")
    all_events: List[Dict[str, Any]] = []
    for path in file_paths:
        check_cancel()
        try:
            all_events.extend(_ingest_file(path))
        except Exception as exc:  # noqa: BLE001
            # Don't let one bad file kill the whole job — surface it in the
            # category counts instead so it's visible in the report.
            all_events.append(
                {
                    "timestamp": None,
                    "event_id": None,
                    "category": "ingest_error",
                    "Details": f"Failed to parse {path.name}: {exc}",
                    "sigma_alerts": [],
                }
            )

    event_category_counts: Dict[str, int] = {}
    for e in all_events:
        cat = e.get("category", "unknown")
        event_category_counts[cat] = event_category_counts.get(cat, 0) + 1

    check_cancel()
    update_stage(job_id, "Running Sigma detection rules")
    all_events = load_and_evaluate_sigma(all_events, rules_dir=str(SIGMA_RULES_DIR))

    check_cancel()
    update_stage(job_id, "Building attack graph & registry state")
    tree_text = build_enriched_tree(all_events)

    check_cancel()

    # --- Alert digest: group by rule title, sorted by severity ---
    grouped: Dict[str, Dict[str, Any]] = {}
    for event in all_events:
        for alert in event.get("sigma_alerts", []) or []:
            title = alert.get("title", "Untitled rule")
            level = _normalize_level(alert.get("level"))
            tags = [str(t) for t in alert.get("tags", [])]
            rule_path = alert.get("rule_path") or "unknown rule path"
            key = title
            if key not in grouped:
                grouped[key] = {
                    "title": title,
                    "level": level,
                    "tags": tags,
                    "rule_path": rule_path,
                    "count": 0,
                    "examples": [],
                }
            g = grouped[key]
            g["count"] += 1
            if len(g["examples"]) < 5:
                g["examples"].append(
                    {
                        "timestamp": event.get("timestamp"),
                        "source": _event_source_label(event),
                        "category": event.get("category"),
                    }
                )

    alerts_by_severity: Dict[str, List[Dict[str, Any]]] = {
        "critical": [], "high": [], "medium": [], "low": [], "informational": [], "unknown": []
    }
    for alert in sorted(grouped.values(), key=lambda a: (_severity_rank(a["level"]), -a["count"])):
        bucket = alert["level"] if alert["level"] in alerts_by_severity else "unknown"
        alerts_by_severity[bucket].append(alert)

    check_cancel()
    update_stage(job_id, f"Generating AI kill-chain report ({OLLAMA_MODEL})")
    ai_report = analyze_with_hybrid_ai(tree_text, model_name=OLLAMA_MODEL)

    return {
        "total_events": len(all_events),
        "event_category_counts": event_category_counts,
        "alerts_by_severity": alerts_by_severity,
        "tree_text": tree_text,
        "ai_report": ai_report,
    }
