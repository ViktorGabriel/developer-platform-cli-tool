"""Parser for Dockerfile contents and AST representation."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DockerfileInstruction:
    """Represents a single parsed Dockerfile directive."""

    instruction: str
    arguments: str
    line_number: int
    raw_content: str


class DockerfileParser:
    """Parses Dockerfiles preserving line numbers and handling multiline continuations."""

    @staticmethod
    def parse_file(file_path: Path) -> list[DockerfileInstruction]:
        """Read and parse a Dockerfile from the filesystem."""
        content = file_path.read_text(encoding="utf-8", errors="replace")
        return DockerfileParser.parse_text(content)

    @staticmethod
    def parse_text(content: str) -> list[DockerfileInstruction]:
        """Parse raw Dockerfile string into structured instructions."""
        lines = content.splitlines()
        instructions: list[DockerfileInstruction] = []

        current_instruction: str | None = None
        current_arguments: list[str] = []
        current_start_line: int = 1
        current_raw_lines: list[str] = []

        for line_idx, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()

            # Skip empty lines or pure comments outside instruction continuation
            if current_instruction is None and (not stripped or stripped.startswith("#")):
                continue

            if current_instruction is None:
                current_start_line = line_idx
                # Match instruction (e.g. FROM, RUN, USER, EXPOSE)
                parts = stripped.split(maxsplit=1)
                current_instruction = parts[0].upper()
                current_arguments = [parts[1]] if len(parts) > 1 else [""]
                current_raw_lines = [raw_line]
            else:
                current_arguments.append(stripped)
                current_raw_lines.append(raw_line)

            # Check if this line ends with continuation character '\'
            if stripped.endswith("\\"):
                # Remove trailing backslash from current chunk
                current_arguments[-1] = current_arguments[-1][:-1].strip()
            else:
                # Instruction completed
                full_args = " ".join(current_arguments).strip()
                instructions.append(
                    DockerfileInstruction(
                        instruction=current_instruction,
                        arguments=full_args,
                        line_number=current_start_line,
                        raw_content="\n".join(current_raw_lines),
                    )
                )
                current_instruction = None
                current_arguments = []
                current_raw_lines = []

        # Handle edge case where last line had a dangling backslash
        if current_instruction is not None:
            instructions.append(
                DockerfileInstruction(
                    instruction=current_instruction,
                    arguments=" ".join(current_arguments).strip(),
                    line_number=current_start_line,
                    raw_content="\n".join(current_raw_lines),
                )
            )

        return instructions
