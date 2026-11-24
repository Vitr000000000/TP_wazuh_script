"""
Export des rapports synthétiques CSV et JSON.
"""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def export_report(
    summary: list[dict[str, Any]],
    out_dir: str = "reports",
) -> tuple[str, str]:
    """
    Écrit un rapport JSON + CSV dans out_dir.
    Retourne (chemin_json, chemin_csv).
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # --- JSON ---
    json_path = Path(out_dir) / f"alert_summary_{ts}.json"
    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # --- CSV ---
    csv_path = Path(out_dir) / f"alert_summary_{ts}.csv"
    fieldnames = ["src_ip", "period", "count", "max_severity", "hosts", "rules","ip_type", "reputation", "threat_score", "enrichment_source"]

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in summary:
            writer.writerow({
                "src_ip": row.get("src_ip", ""),
                "period": row.get("period", ""),
                "count": row.get("count", 0),
                "max_severity": row.get("max_severity", 0),
                "hosts": ";".join(row.get("hosts") or []),
                "rules": ";".join(row.get("rules") or []),
                "ip_type": row.get("ip_type", ""),
                "reputation": row.get("reputation", ""),
                "threat_score": row.get("threat_score", ""),
                "enrichment_source": row.get("enrichment_source", ""),
            })

    return str(json_path), str(csv_path)
