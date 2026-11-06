"""Shared test fixtures."""

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def vulnerable_dockerfile(fixtures_dir: Path) -> Path:
    return fixtures_dir / "Dockerfile.vulnerable"


@pytest.fixture
def secure_dockerfile(fixtures_dir: Path) -> Path:
    return fixtures_dir / "Dockerfile.secure"


@pytest.fixture
def vulnerable_config_yaml(fixtures_dir: Path) -> Path:
    return fixtures_dir / "config_vulnerable.yaml"


@pytest.fixture
def vulnerable_config_json(fixtures_dir: Path) -> Path:
    return fixtures_dir / "config_vulnerable.json"


@pytest.fixture
def secure_config_yaml(fixtures_dir: Path) -> Path:
    return fixtures_dir / "config_secure.yaml"
