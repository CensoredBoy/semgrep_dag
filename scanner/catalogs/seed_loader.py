"""
SeedLoader -- loads initial data from YAML/JSON files into catalogs.

Linking convention:
  - Detectors loaded from each file are tracked by filename
    (e.g. jailbreak.yaml -> group "jailbreak").
  - source field in YAML is purely informational ("garak", "custom").
  - Attacks reference detector groups via `detector_file` key,
    which resolves to detector IDs loaded from that file.
  - Prompts are linked by `prompt_tags`.
  - Tools are linked by `tool_names`.
  - All M:N links use data model join tables (by ID).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from scanner.catalogs.catalogs import (
    AttackCatalog,
    AttackerCatalog,
    DetectorCatalog,
    JudgeCatalog,
    PromptCatalog,
    ToolCatalog,
)
from scanner.data.models import (
    Attack,
    DetectorSubstring,
    Prompt,
    Tool,
)

logger = logging.getLogger(__name__)


def _load_file(path: Path) -> list[dict[str, Any]]:
    """Load YAML or JSON file and return list of dicts."""
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    if isinstance(data, dict) and "items" in data:
        return data["items"]
    if isinstance(data, list):
        return data
    return [data]


class SeedLoader:
    """Loads seed data from asset directories into the database."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.prompts = PromptCatalog(session)
        self.attackers = AttackerCatalog(session)
        self.detectors = DetectorCatalog(session)
        self.judges = JudgeCatalog(session)
        self.tools = ToolCatalog(session)
        self.attacks = AttackCatalog(session)
        # Mapping: filename stem -> list of DetectorSubstring IDs
        self._detector_file_map: dict[str, list[str]] = {}

    def load_all(self, assets_dir: str | Path) -> dict[str, int]:
        base = Path(assets_dir)
        counts: dict[str, int] = {}
        counts["prompts"] = self._load_prompts(base / "prompts")
        counts["attacker_instructions"] = self._load_attackers(base / "attacker_instructions")
        counts["detector_substrings"] = self._load_detectors(base / "detector_substrings")
        counts["judge_instructions"] = self._load_judges(base / "judge_instructions")
        counts["tools"] = self._load_tools(base / "tools")
        counts["attacks"] = self._load_attacks(base / "attacks")
        return counts

    def _load_prompts(self, directory: Path) -> int:
        if not directory.exists():
            return 0
        count = 0
        for path in sorted(directory.glob("*.y*ml")) + sorted(directory.glob("*.json")):
            for item in _load_file(path):
                try:
                    self.prompts.add_prompt(
                        content=item["content"],
                        source=item.get("source", path.stem),
                        language=item.get("language", "en"),
                        tags=item.get("tags", []),
                    )
                    count += 1
                except Exception:
                    self.session.rollback()
                    logger.debug("Skipping duplicate prompt: %s...", item.get("content", "")[:60])
        logger.info("Loaded %d prompts", count)
        return count

    def _load_attackers(self, directory: Path) -> int:
        if not directory.exists():
            return 0
        count = 0
        for path in sorted(directory.glob("*.y*ml")) + sorted(directory.glob("*.json")):
            for item in _load_file(path):
                try:
                    self.attackers.add_instruction(
                        name=item["name"],
                        system_prompt=item["system_prompt"],
                        description=item.get("description", ""),
                    )
                    count += 1
                except Exception:
                    self.session.rollback()
                    logger.debug("Skipping duplicate attacker: %s", item.get("name"))
        logger.info("Loaded %d attacker instructions", count)
        return count

    def _load_detectors(self, directory: Path) -> int:
        """Load detector substrings and track IDs per filename for attack linking."""
        if not directory.exists():
            return 0
        count = 0
        for path in sorted(directory.glob("*.y*ml")) + sorted(directory.glob("*.json")):
            file_key = path.stem  # e.g. "jailbreak", "tool_abuse"
            ids_for_file: list[str] = []
            for item in _load_file(path):
                try:
                    entity = self.detectors.add_substring(
                        substring=item["substring"],
                        source=item.get("source", "custom"),
                        is_negation=item.get("is_negation", False),
                        description=item.get("description", ""),
                    )
                    ids_for_file.append(entity.id)
                    count += 1
                except Exception:
                    self.session.rollback()
                    logger.debug("Skipping duplicate detector substring")
            self._detector_file_map[file_key] = ids_for_file
        logger.info("Loaded %d detector substrings", count)
        return count

    def _load_judges(self, directory: Path) -> int:
        if not directory.exists():
            return 0
        count = 0
        for path in sorted(directory.glob("*.y*ml")) + sorted(directory.glob("*.json")):
            for item in _load_file(path):
                try:
                    self.judges.add_instruction(
                        name=item["name"],
                        system_prompt=item["system_prompt"],
                        true_description=item["true_description"],
                        description=item.get("description", ""),
                    )
                    count += 1
                except Exception:
                    self.session.rollback()
                    logger.debug("Skipping duplicate judge: %s", item.get("name"))
        logger.info("Loaded %d judge instructions", count)
        return count

    def _load_tools(self, directory: Path) -> int:
        if not directory.exists():
            return 0
        count = 0
        for path in sorted(directory.glob("*.y*ml")) + sorted(directory.glob("*.json")):
            for item in _load_file(path):
                try:
                    self.tools.add_tool(
                        name=item["name"],
                        description=item.get("description", ""),
                        parameters_schema=item.get("parameters_schema", {}),
                    )
                    count += 1
                except Exception:
                    self.session.rollback()
                    logger.debug("Skipping duplicate tool: %s", item.get("name"))
        logger.info("Loaded %d tools", count)
        return count

    def _load_attacks(self, directory: Path) -> int:
        if not directory.exists():
            return 0
        count = 0
        for path in sorted(directory.glob("*.y*ml")) + sorted(directory.glob("*.json")):
            for item in _load_file(path):
                try:
                    self._create_attack(item)
                    count += 1
                except Exception as e:
                    self.session.rollback()
                    logger.warning("Failed to load attack %s: %s", item.get("name"), e)
        logger.info("Loaded %d attacks", count)
        return count

    def _create_attack(self, item: dict[str, Any]) -> Attack:
        """Create Attack, linking all components by ID via data model."""
        with self.session.no_autoflush:
            # Resolve FK references
            attacker_instr = None
            if item.get("attacker_instruction"):
                attacker_instr = self.attackers.get_by_name(item["attacker_instruction"])

            judge_instr = None
            if item.get("judge_instruction"):
                judge_instr = self.judges.get_by_name(item["judge_instruction"])

            attack = Attack(
                name=item["name"],
                category=item["category"],
                description=item.get("description", ""),
                orchestrator_type=item.get("orchestrator_type", "prompt_sending"),
                scorer_type=item.get("scorer_type", "substring"),
                max_turns=item.get("max_turns", 1),
                converter_chain=json.dumps(item.get("converter_chain", [])),
                is_negation=item.get("is_negation", False),
                attacker_instruction=attacker_instr,
                judge_instruction=judge_instr,
            )
            self.session.add(attack)

            # Link prompts by tags (M:N via attack_prompt join table, by ID)
            if item.get("prompt_tags"):
                stmt = select(Prompt).where(Prompt.is_active == True)  # noqa: E712
                for tag in item["prompt_tags"]:
                    stmt = stmt.where(Prompt.tags.contains(tag))
                attack.prompts = list(self.session.execute(stmt).scalars().all())

            # Link detectors by file group (M:N via attack_detector_substring, by ID)
            if item.get("detector_file"):
                file_key = item["detector_file"]
                detector_ids = self._detector_file_map.get(file_key, [])
                if detector_ids:
                    stmt = select(DetectorSubstring).where(DetectorSubstring.id.in_(detector_ids))
                    attack.detector_substrings = list(self.session.execute(stmt).scalars().all())
                else:
                    logger.warning("No detectors found for file group: %s", file_key)

            # Link tools by name (M:N via attack_tool join table, by ID)
            if item.get("tool_names"):
                stmt = select(Tool).where(Tool.name.in_(item["tool_names"]))
                attack.tools = list(self.session.execute(stmt).scalars().all())

        self.session.commit()
        self.session.refresh(attack)
        return attack
