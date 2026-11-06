"""Parser and inspector for local Docker containers."""

from dataclasses import dataclass
from typing import Any

import docker
from docker.errors import DockerException


@dataclass(frozen=True)
class ContainerInfo:
    """Normalized metadata for a local Docker container."""

    id: str
    name: str
    image: str
    status: str
    user: str
    privileged: bool
    exposed_ports: list[str]
    port_bindings: dict[str, list[dict[str, str]]]
    env_vars: list[str]


class ContainerParser:
    """Inspects running and stopped containers using Docker Engine API."""

    def __init__(self, client: docker.DockerClient | None = None) -> None:
        self._client = client

    def get_client(self) -> docker.DockerClient:
        """Initialize or return active Docker client."""
        if self._client is None:
            try:
                self._client = docker.from_env()
                self._client.ping()
            except DockerException as err:
                raise RuntimeError(
                    f"Não foi possível conectar ao Docker daemon: {err}. "
                    "Verifique se o Docker Desktop ou o serviço Docker está em execução."
                ) from err
        return self._client

    def list_containers(
        self, all_containers: bool = False, container_id: str | None = None
    ) -> list[ContainerInfo]:
        """Fetch and normalize container details from Docker."""
        client = self.get_client()
        containers_to_check: list[Any] = []

        if container_id:
            try:
                container = client.containers.get(container_id)
                containers_to_check.append(container)
            except docker.errors.NotFound as err:
                raise ValueError(f"Contêiner '{container_id}' não foi encontrado.") from err
        else:
            containers_to_check = client.containers.list(all=all_containers)

        results: list[ContainerInfo] = []
        for c in containers_to_check:
            attrs = c.attrs or {}
            config = attrs.get("Config", {})
            host_config = attrs.get("HostConfig", {})
            network_settings = attrs.get("NetworkSettings", {})

            # Resolve ports
            ports_config = config.get("ExposedPorts") or {}
            ports_list = list(ports_config.keys())

            bindings = host_config.get("PortBindings") or network_settings.get("Ports") or {}

            user = config.get("User", "")
            privileged = host_config.get("Privileged", False)
            env_vars = config.get("Env", [])

            results.append(
                ContainerInfo(
                    id=c.short_id if hasattr(c, "short_id") else c.id[:12],
                    name=c.name.lstrip("/"),
                    image=c.image.tags[0] if c.image and c.image.tags else str(c.image),
                    status=c.status,
                    user=user,
                    privileged=privileged,
                    exposed_ports=ports_list,
                    port_bindings=bindings,
                    env_vars=env_vars,
                )
            )

        return results
