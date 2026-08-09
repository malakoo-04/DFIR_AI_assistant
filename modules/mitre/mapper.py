from __future__ import annotations

from modules.mitre.mapping import RULE_TO_MITRE


class MITREMapper:
    """
    Deterministically assign MITRE ATT&CK techniques
    to correlations.

    No AI.
    No reasoning.

    Each correlation receives the ATT&CK techniques
    associated with the correlation rule that generated it.
    """

    def map(self, correlations):

        for correlation in correlations:

            correlation.techniques = list(
                RULE_TO_MITRE.get(
                    correlation.rule_name,
                    [],
                )
            )

        return correlations