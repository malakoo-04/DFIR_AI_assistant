from __future__ import annotations

import json


class FinalReportPromptBuilder:

    def build(
        self,
        prioritized_incidents: list[dict],
        investigation_report: str,
        ioc_report: str,
    ) -> str:

        return "\n\n".join(
            [
                self._build_system(),
                self._build_task(),
                self._build_context(
                    prioritized_incidents,
                    investigation_report,
                    ioc_report,
                ),
                self._build_output_contract(),
            ]
        )

    # ---------------------------------------------------------

    @staticmethod
    def _build_system() -> str:

        return """
Vous êtes un expert senior en Digital Forensics & Incident Response (DFIR).

Votre rôle est de produire le rapport DFIR final destiné à un analyste SOC, un responsable cybersécurité ou un expert en réponse à incident.

Vous ne devez PAS refaire l'investigation.

Vous ne devez PAS découvrir de nouveaux IOC, techniques MITRE ou scénarios d'attaque.

Votre unique mission est de synthétiser les résultats déjà produits.

Toutes les conclusions doivent être directement justifiées par les preuves présentes dans le rapport d'investigation, le rapport IOC et le résumé des incidents.

Lorsque les preuves sont insuffisantes, indiquez explicitement que la conclusion ne peut pas être démontrée.

Le rapport doit être rédigé dans un style professionnel similaire aux rapports publiés par The DFIR Report.

Le rapport doit être clair, concis, cohérent et éviter toute répétition inutile.
""".strip()

    # ---------------------------------------------------------

    @staticmethod
    def _build_task() -> str:

        return """
MISSION

Produire un rapport final DFIR professionnel en français.

Le rapport doit contenir exactement les sections suivantes.

1. Résumé exécutif

Présenter en quelques paragraphes :

- nature de l'incident
- période analysée
- niveau de confiance global
- principaux résultats de l'investigation

Ne pas entrer dans les détails techniques.

------------------------------------------------------------

2. Artefacts analysés

Présenter un résumé des éléments ayant permis l'investigation.

Mentionner notamment :

- incidents analysés
- chronologie
- journaux Windows
- registre
- Prefetch
- PowerShell
- navigateurs
- autres artefacts lorsque présents

Ne pas inventer de statistiques.

------------------------------------------------------------

3. Synthèse de l'attaque

Décrire le scénario global de l'attaque.

Fusionner les informations provenant de l'investigation sans répéter plusieurs fois les mêmes faits.

------------------------------------------------------------

4. Chronologie de l'attaque

Présenter la chronologie dans l'ordre chronologique.

Pour chaque étape préciser :

- heure
- action
- preuve principale

------------------------------------------------------------

5. Chaîne d'attaque

Présenter les différentes étapes observées.

Pour chaque étape :

- objectif
- actions réalisées
- preuves associées

Si une étape n'est pas démontrée, écrire "Non déterminé".

------------------------------------------------------------

6. Techniques MITRE ATT&CK observées

Présenter cette section sous forme de tableau.

Colonnes :

- Technique ID
- Technique
- Tactique
- Incidents
- Corrélations
- Justification

Ne jamais ajouter une technique absente des preuves.

------------------------------------------------------------

7. Indicateurs de compromission (IOC)

Regrouper les IOC par catégories :

- Réseau
- Fichiers
- Processus
- Commandes
- Registre

Supprimer les doublons.

------------------------------------------------------------

8. Comportements suspects

Identifier uniquement les comportements déjà démontrés.

Pour chacun :

- comportement
- niveau de confiance
- preuves
- impact potentiel

------------------------------------------------------------

9. Impact

Séparer cette section en :

- Impact technique
- Impact potentiel sur les données
- Impact opérationnel

Lorsque l'information est inconnue, écrire explicitement "Non déterminé".

------------------------------------------------------------

10. Conclusions

Résumer les principales conclusions de l'investigation.

Chaque conclusion doit être directement supportée par les preuves.

------------------------------------------------------------

11. Recommandations

Organiser les recommandations selon les catégories suivantes :

- Confinement
- Éradication
- Restauration
- Durcissement
- Surveillance

Ne proposer que des recommandations pertinentes par rapport aux preuves observées.

------------------------------------------------------------

Règles générales

- Ne jamais inventer de nouvelles preuves.
- Ne jamais inventer de nouveaux IOC.
- Ne jamais inventer de nouvelles techniques MITRE.
- Fusionner les informations similaires.
- Éviter toute répétition.
- Employer un vocabulaire professionnel.
- Préférer les formulations :

  "Les preuves indiquent..."
  "Les artefacts montrent..."
  "L'investigation met en évidence..."

plutôt que des affirmations absolues lorsqu'une certitude totale n'est pas démontrée.
""".strip()

    # ---------------------------------------------------------

    @staticmethod
    def _build_context(
        prioritized_incidents: list[dict],
        investigation_report: str,
        ioc_report: str,
    ) -> str:

        simplified_incidents = []

        for incident in prioritized_incidents:

            simplified_incidents.append(
                {
                    "incident_id": incident.get("incident_id"),
                    "severity": incident.get("severity"),
                    "confidence": incident.get("confidence"),
                    "time_window": incident.get("time_window"),

                    "rules": incident.get("rules", []),

                    "entities": [
                        entity.get("entity_id", entity)
                        if isinstance(entity, dict)
                        else entity
                        for entity in incident.get("entities", [])
                    ],

                    "techniques": sorted(
                        {
                            technique
                            for correlation in (
                                incident.get("primary_correlations", [])
                                + incident.get("supporting_correlations", [])
                            )
                            for technique in correlation.get("techniques", [])
                        }
                    ),
                }
            )

        text = "\n\n".join(
            [
                "==============================",
                "RAPPORT D'INVESTIGATION",
                "==============================",
                investigation_report,

                "",

                "==============================",
                "RAPPORT IOC",
                "==============================",
                ioc_report,

                "",

                
            ]
        )

        print(f"Final prompt size: {len(text):,} chars")

        return text    

        
    # ---------------------------------------------------------

    @staticmethod
    def _build_output_contract() -> str:

            return """
CONTRAINTES

Retournez uniquement le rapport DFIR final.

N'utilisez jamais de JSON.

N'utilisez jamais de Markdown.

N'utilisez jamais de blocs de code.

Utilisez des titres et sous-titres professionnels.

Le rapport doit être directement exploitable par un analyste SOC ou une équipe DFIR.

Toutes les conclusions doivent être justifiées par les preuves fournies.

Ne répétez jamais plusieurs fois les mêmes informations.

Privilégiez des tableaux lorsque cela améliore la lisibilité, notamment pour les techniques MITRE ATT&CK et les IOC.

Lorsque certaines informations ne peuvent pas être démontrées par les preuves, indiquez explicitement qu'elles sont non déterminées.

Le rapport doit être rédigé dans un style comparable aux rapports publiés par The DFIR Report.
""".strip()