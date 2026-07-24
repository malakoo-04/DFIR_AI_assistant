from pathlib import Path
import xml.etree.ElementTree as ET
from datetime import datetime

from modules.parsers.base_parser import BaseParser


class ScheduledTaskParser(BaseParser):
    """
    Parser for Windows Scheduled Tasks (.xml).
    """

    NS = {
        "task": "http://schemas.microsoft.com/windows/2004/02/mit/task"
    }

    def parse(self, artifact_path: Path) -> list[dict]:

        try:
            tree = ET.parse(artifact_path)
            root = tree.getroot()

        except Exception:
            return []

        registration = root.find("task:RegistrationInfo", self.NS)
        principals = root.find("task:Principals", self.NS)
        settings = root.find("task:Settings", self.NS)
        actions = root.find("task:Actions", self.NS)
        triggers = root.find("task:Triggers", self.NS)

        registration_date = self._text(
            registration,
            "task:Date"
        )

        task_name = artifact_path.name

        command = None
        arguments = None
        working_directory = None

        exec_node = None

        if actions is not None:
            exec_node = actions.find("task:Exec", self.NS)

        if exec_node is not None:

            command = self._text(exec_node, "task:Command")

            arguments = self._text(exec_node, "task:Arguments")

            working_directory = self._text(
                exec_node,
                "task:WorkingDirectory"
            )

        user = None
        run_level = None

        if principals is not None:

            principal = principals.find(
                "task:Principal",
                self.NS
            )

            if principal is not None:

                user = self._text(
                    principal,
                    "task:UserId"
                )

                run_level = self._text(
                    principal,
                    "task:RunLevel"
                )

        enabled = True
        hidden = False

        if settings is not None:

            enabled_text = self._text(
                settings,
                "task:Enabled"
            )

            hidden_text = self._text(
                settings,
                "task:Hidden"
            )

            enabled = (
                enabled_text.lower() == "true"
                if enabled_text
                else True
            )

            hidden = (
                hidden_text.lower() == "true"
                if hidden_text
                else False
            )

        trigger_types = []

        if triggers is not None:

            for trigger in triggers:

                tag = trigger.tag.split("}")[-1]

                trigger_types.append(tag)

        author = None
        description = None

        if registration is not None:

            author = self._text(
                registration,
                "task:Author"
            )

            description = self._text(
                registration,
                "task:Description"
            )

        return [

            {

                "artifact_type": "scheduled_task",

                "task_name": task_name,

                "author": author,

                "description": description,

                "registration_date": self._parse_datetime(
                    registration_date
                ),

                "command": command,

                "arguments": arguments,

                "working_directory": working_directory,

                "user": user,

                "run_level": run_level,

                "enabled": enabled,

                "hidden": hidden,

                "triggers": trigger_types,

                "source_path": str(artifact_path)

            }

        ]

    def _text(self, node, path):

        if node is None:
            return None

        child = node.find(path, self.NS)

        if child is None:
            return None

        return child.text

    def _parse_datetime(self, value):

        if not value:
            return None

        try:

            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

        except Exception:

            return value