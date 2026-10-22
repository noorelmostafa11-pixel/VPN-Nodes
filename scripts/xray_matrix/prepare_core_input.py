"""Expand list records using VPN-Nodes' helper linked to the unchanged core."""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from owned_core import PUBLIC_PROTOCOL, digest, validate_manifest


def prepare_rows(rows: list[dict], tool: Path, manifest: dict) -> list[dict]:
    validate_manifest(manifest)
    if (manifest.get("input_core_revision") != manifest["revision"]
            or manifest.get("input_binary_sha256") != digest(tool)
            or not manifest.get("input_tool_revision")):
        raise ValueError("Input helper does not match the pinned core build")
    with tempfile.TemporaryDirectory(prefix="vpn-node-input-") as directory:
        source = Path(directory) / "source.jsonl"
        output = Path(directory) / "expanded.jsonl"
        with source.open("w", encoding="utf-8", newline="\n") as stream:
            for row in rows:
                raw = row.get("uri")
                if not isinstance(raw, str) or not raw or any(c in raw for c in "\r\n"):
                    raise ValueError("Invalid candidate input framing")
                stream.write(json.dumps({"uri": raw}, ensure_ascii=False) + "\n")
        subprocess.run([str(tool.resolve()), "-input", str(source), "-output", str(output)], check=True)
        prepared = []
        with output.open(encoding="utf-8") as stream:
            header = json.loads(next(stream, "{}"))
            if header != {"schema": "vpn-node-input-v1", "revision": manifest["revision"],
                          "tool_revision": manifest["input_tool_revision"], "input_sha256": digest(source)}:
                raise ValueError("Input helper provenance mismatch")
            for index, row in enumerate(rows):
                record = json.loads(next(stream, "{}"))
                entries = record.get("entries")
                if (type(record.get("index")) is not int or record["index"] != index
                        or not isinstance(entries, list) or not 1 <= len(entries) <= 8):
                    raise ValueError("Input helper source coverage mismatch")
                if len(entries) == 1 and entries[0] == {"uri": row["uri"]}:
                    prepared.append(dict(row))
                    continue
                if len(entries) < 2:
                    raise ValueError("Input helper changed an ordinary node")
                for component, entry in enumerate(entries):
                    raw, protocol = entry.get("uri"), entry.get("protocol")
                    if (not isinstance(raw, str) or not raw or any(c in raw for c in "\r\n")
                            or protocol not in PUBLIC_PROTOCOL
                            or not isinstance(entry.get("host"), str) or not entry["host"]
                            or type(entry.get("port")) is not int or not 1 <= entry["port"] <= 65535):
                        raise ValueError("Invalid expanded candidate identity")
                    candidate = dict(row, **entry, joined_original_uri=row["uri"],
                                     joined_component=component, joined_components=len(entries))
                    # The child's endpoint must receive its own normal TCP precheck.
                    for field in ("latency_ms", "liveness", "country", "country_resolution"):
                        candidate.pop(field, None)
                    prepared.append(candidate)
            if next(stream, None) is not None:
                raise ValueError("Input helper returned foreign source records")
    return prepared
