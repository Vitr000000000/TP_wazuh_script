"""
Enrichissement des IP avec une base locale de démonstration.
"""

import ipaddress


# Données fictives utilisées uniquement pour le TP.
MOCK_DATABASE = {
    "203.0.113.42": {
        "reputation": "suspicious",
        "threat_score": 85,
    }
}


def enrich_summary(summary: list[dict]) -> list[dict]:
    for group in summary:
        ip = group["src_ip"]

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            group.update({
                "ip_type": "invalid",
                "reputation": "unknown",
                "threat_score": None,
                "enrichment_source": "none",
            })
            continue

        if not address.is_global:
            group.update({
                "ip_type": "private",
                "reputation": "not_applicable",
                "threat_score": None,
                "enrichment_source": "local_ip_classification",
            })
            continue

        result = MOCK_DATABASE.get(ip)

        if result:
            group.update({
                "ip_type": "public",
                **result,
                "enrichment_source": "mock_database",
            })
        else:
            group.update({
                "ip_type": "public",
                "reputation": "unknown",
                "threat_score": None,
                "enrichment_source": "mock_database",
            })

    return summary
