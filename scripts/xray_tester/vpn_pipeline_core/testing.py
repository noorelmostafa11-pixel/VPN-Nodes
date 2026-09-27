from __future__ import annotations

from pathlib import Path

from .config import REAL_PING_URL
from .models import Node, TestResult
from .parsers import PARSERS
from .repairs import repair_candidate_for_failure
from .results import validate_completeness
from .storage import log
from .xray_engine import classify_parser_failure, run_v2rayn_real_ping_batch


def run_protocol_role(
    protocol: str,
    role: str,
    indexed_nodes: list[tuple[int, str]],
    xray: Path,
    run_dir: Path,
    source_sha: str,
) -> list[TestResult]:
    """Test one worker/protocol using only the Xray Real Delay decision path.

    Valid share formats are translated completely by the parser before the
    first Xray run.  A derived repair is considered only for a malformed source
    that produced ``source_invalid``/``unsupported`` and only when repairs.py can
    build a non-guessing candidate from the source text itself.
    """
    del source_sha
    parser = PARSERS[protocol]
    parsed: list[Node] = []
    base_results: dict[int, TestResult] = {}

    log(
        f"[{role.upper()}:{protocol}] Parsing {len(indexed_nodes):,} nodes "
        "for Xray single HTTPS response (engine-first; one configured target)"
    )

    for global_index, raw in indexed_nodes:
        try:
            parsed.append(parser(raw, global_index, REAL_PING_URL))
        except Exception as exc:
            base_results[global_index] = TestResult(
                protocol, global_index, raw, "", 0, False,
                classify_parser_failure(exc), f"{type(exc).__name__}: {exc}",
            )

    if parsed:
        xray_log = run_dir / f"{role}_{protocol}_xray.log"
        for row in run_v2rayn_real_ping_batch(parsed, xray, xray_log):
            base_results[row.index] = row

    # Build at most one *composed* candidate per failed source.  This is not a
    # chain of speculative retries: every transformation is source-derived, and
    # the final explicit URI is tested once with the normal Real Delay engine.
    repair_nodes: list[Node] = []
    repair_meta: dict[int, tuple[str, str, TestResult]] = {}
    for global_index, source_raw in indexed_nodes:
        original = base_results.get(global_index)
        if original is None or original.ok:
            continue
        candidate = repair_candidate_for_failure(original)
        if candidate is None:
            continue
        repaired_raw, strategy = candidate
        try:
            repaired_node = parser(repaired_raw, global_index, REAL_PING_URL)
        except Exception as exc:
            original.error = (
                f"{original.error}; repair[{strategy}] parser failed: "
                f"{type(exc).__name__}: {exc}"
            )
            continue
        repair_nodes.append(repaired_node)
        repair_meta[global_index] = (source_raw, strategy, original)

    if repair_nodes:
        repair_log = run_dir / f"{role}_{protocol}_repair_xray.log"
        repaired_rows = run_v2rayn_real_ping_batch(repair_nodes, xray, repair_log)
        for repaired in repaired_rows:
            source_raw, strategy, original = repair_meta[repaired.index]
            if repaired.ok:
                repaired.source_raw = source_raw
                repaired.repair_strategy = strategy
                repaired.real_delay_proven = True
                base_results[repaired.index] = repaired
            else:
                # Publication identity stays the original source on repair
                # failure, while the diagnostic records how far the explicit
                # candidate progressed.
                base_results[repaired.index] = TestResult(
                    protocol=original.protocol,
                    index=original.index,
                    raw=source_raw,
                    host=original.host,
                    port=original.port,
                    ok=False,
                    stage=repaired.stage,
                    error=(
                        f"original[{original.stage}]: {original.error}; "
                        f"repair[{strategy}][{repaired.stage}]: {repaired.error}"
                    ),
                    tcp_ms=repaired.tcp_ms,
                    http204_ms=repaired.http204_ms,
                    country="XX",
                )

    output = [base_results[index] for index, _ in indexed_nodes]
    validate_completeness(output, [index for index, _ in indexed_nodes])
    return output


# Backward-compatible production wrapper for callers that still import the old
# public symbol.  The active pipeline uses run_protocol_role; pytest is told
# explicitly that this compatibility wrapper is not a test case.
def test_protocol_role(
    protocol: str,
    role: str,
    indexed_nodes: list[tuple[int, str]],
    xray: Path,
    run_dir: Path,
    source_sha: str,
) -> list[TestResult]:
    return run_protocol_role(protocol, role, indexed_nodes, xray, run_dir, source_sha)

test_protocol_role.__test__ = False
