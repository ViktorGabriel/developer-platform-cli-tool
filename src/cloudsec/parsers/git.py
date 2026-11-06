"""Parser and runner for Git history and diff extraction."""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GitCommitDiff:
    """Represents an added/modified line in a specific Git commit."""

    commit_hash: str
    author: str
    date: str
    message: str
    file_path: str
    line_number: int | None
    added_content: str


HUNK_HEADER_REGEX = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitParser:
    """Executes Git commands and parses diff streams."""

    @staticmethod
    def get_commit_diffs(repo_path: Path, max_commits: int = 10) -> list[GitCommitDiff]:
        """Run 'git log -p' and extract newly added lines across recent commits."""
        git_dir = repo_path / ".git"
        if not git_dir.exists():
            raise RuntimeError(
                f"O diretório '{repo_path}' não é a raiz de um repositório Git (.git não encontrado)."
            )

        cmd = [
            "git",
            "-C",
            str(repo_path),
            "log",
            f"-n{max_commits}",
            "--format=COMMIT_META:%H|%an|%ad|%s",
            "-p",
            "--no-color",
        ]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                encoding="utf-8",
                errors="replace",
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as err:
            raise RuntimeError(
                f"Falha ao executar comando Git no diretório '{repo_path}': {err}"
            ) from err

        return GitParser.parse_git_log_output(process.stdout)

    @staticmethod
    def parse_git_log_output(log_output: str) -> list[GitCommitDiff]:
        """Parse the raw text of 'git log -p' into structured commit diff entries."""
        diff_entries: list[GitCommitDiff] = []

        current_hash = ""
        current_author = ""
        current_date = ""
        current_message = ""
        current_file = ""
        current_line_no = 0

        for line in log_output.splitlines():
            if line.startswith("COMMIT_META:"):
                meta_parts = line[len("COMMIT_META:") :].split("|", maxsplit=3)
                current_hash = meta_parts[0] if len(meta_parts) > 0 else ""
                current_author = meta_parts[1] if len(meta_parts) > 1 else ""
                current_date = meta_parts[2] if len(meta_parts) > 2 else ""
                current_message = meta_parts[3] if len(meta_parts) > 3 else ""
                current_file = ""
                current_line_no = 0
                continue

            if line.startswith("diff --git "):
                # diff --git a/path/to/file b/path/to/file
                parts = line.split(" ")
                if len(parts) >= 4 and parts[3].startswith("b/"):
                    current_file = parts[3][2:]
                else:
                    current_file = "unknown"
                current_line_no = 0
                continue

            hunk_match = HUNK_HEADER_REGEX.match(line)
            if hunk_match:
                current_line_no = int(hunk_match.group(1))
                continue

            # Check if this line is an added line
            if line.startswith("+") and not line.startswith("+++"):
                added_text = line[1:].strip()
                if added_text and current_file:
                    diff_entries.append(
                        GitCommitDiff(
                            commit_hash=current_hash,
                            author=current_author,
                            date=current_date,
                            message=current_message,
                            file_path=current_file,
                            line_number=current_line_no if current_line_no > 0 else None,
                            added_content=added_text,
                        )
                    )
                if current_line_no > 0:
                    current_line_no += 1
            elif not line.startswith("-"):
                # Context line (unchanged) advances the line count in the new file
                if current_line_no > 0:
                    current_line_no += 1

        return diff_entries
