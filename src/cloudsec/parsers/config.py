"""Parser for YAML and JSON configuration files."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ConfigEntry:
    """Represents a key-value entry discovered in a YAML or JSON configuration."""

    key_path: str
    value: Any
    line_number: int | None
    raw_line: str


class ConfigParser:
    """Parses JSON and YAML configurations preserving context for secret detection."""

    @staticmethod
    def parse_file(file_path: Path) -> tuple[dict[str, Any] | list[Any], list[ConfigEntry]]:
        """Parse a YAML or JSON file and return structured object and entries list."""
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return ConfigParser.parse_text(content, suffix=file_path.suffix.lower())

    @staticmethod
    def parse_text(
        content: str, suffix: str = ".yaml"
    ) -> tuple[dict[str, Any] | list[Any], list[ConfigEntry]]:
        """Parse YAML/JSON content text."""
        parsed_data: Any
        if suffix in (".json",):
            try:
                parsed_data = json.loads(content)
            except json.JSONDecodeError as err:
                raise ValueError(f"Formato JSON inválido: {err}") from err
        else:
            try:
                parsed_data = yaml.safe_load(content)
            except yaml.YAMLError as err:
                raise ValueError(f"Formato YAML inválido: {err}") from err

        raw_lines = content.splitlines()
        entries: list[ConfigEntry] = []

        def locate_line(key_name: str, str_val: str) -> tuple[int | None, str]:
            """Locate best matching line number and line text in raw content."""
            key_clean = key_name.split(".")[-1].strip()
            for idx, line in enumerate(raw_lines, start=1):
                if key_clean in line:
                    return idx, line.strip()
            return None, f"{key_clean}: {str_val}"

        def traverse(node: Any, current_path: str = "") -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    sub_path = f"{current_path}.{k}" if current_path else str(k)
                    if isinstance(v, (dict, list)):
                        traverse(v, sub_path)
                    else:
                        line_no, line_txt = locate_line(str(k), str(v))
                        entries.append(
                            ConfigEntry(
                                key_path=sub_path,
                                value=v,
                                line_number=line_no,
                                raw_line=line_txt,
                            )
                        )
            elif isinstance(node, list):
                for idx, item in enumerate(node):
                    sub_path = f"{current_path}[{idx}]"
                    if isinstance(item, (dict, list)):
                        traverse(item, sub_path)
                    else:
                        line_no, line_txt = locate_line(sub_path, str(item))
                        entries.append(
                            ConfigEntry(
                                key_path=sub_path,
                                value=item,
                                line_number=line_no,
                                raw_line=line_txt,
                            )
                        )

        if parsed_data is not None:
            traverse(parsed_data)

        return parsed_data, entries
