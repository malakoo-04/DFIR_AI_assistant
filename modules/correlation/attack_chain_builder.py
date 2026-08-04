

from collections import defaultdict


class AttackChainBuilder:
    """
    Build a high-level chronological attack chain from correlated incidents.
    """

    STAGE_ORDER = [
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "credential_access",
        "discovery",
        "lateral_movement",
        "defense_evasion",
        "collection",
        "command_and_control",
        "exfiltration",
        "impact",
    ]

    def build(self, incidents):

        stage_map = defaultdict(list)

        for incident in incidents:

            for corr in incident.get("primary_correlations", []):

                stage = corr.get("attack_stage")

                if stage:
                    stage_map[stage].append(corr)

        attack_chain = []

        for stage in self.STAGE_ORDER:

            if stage not in stage_map:
                continue

            first = stage_map[stage][0]

            attack_chain.append(
                {
                    "stage": stage,
                    "count": len(stage_map[stage]),
                    "title": first.get("title", ""),
                    "confidence": first.get("confidence"),
                }
            )

        return attack_chain