import json

content = '''"""
V3.0 Lab Environment Orchestrator

Manages local Docker lab container lifecycle for automated vulnerability verification.
"""

import json
import logging
import shutil
import subprocess
import threading
import time
import uuid as _uuid_mod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class LabStatus(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    ERROR = "error"
    DEGRADED = "degraded"


class ContainerBackend(str, Enum):
    DOCKER = "docker"
    PODMAN = "podman"
    NONE = "none"


@dataclass
class LabTarget:
    name: str
    image: str = ""
    dockerfile_path: str = ""
    internal_port: int = 80
    host_port: int = 0
    env_vars: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 60


@dataclass
class ContainerInfo:
    container_id: str
    name: str
    status: LabStatus
    host_port: int
    internal_port: int
    image: str
    created_at: str = ""
    started_at: str = ""
    health: str = "unknown"


class LabEnvironment:
    """Lab environment orchestrator - manages Docker lab container lifecycle."""

    PORT_RANGE_START = 18080
    PORT_RANGE_END = 18099

    def __init__(self, backend=None, project_root=None, state_file=None):
        self._lock = threading.Lock()
        self._used_ports = set()
        self._containers = {}
        self.project_root = project_root or "."
        self.state_file = state_file or str(Path(self.project_root) / ".lab_state.json")
        if backend is None:
            backend = self._detect_backend()
        self.backend = backend
        self._load_state()

    @staticmethod
    def _detect_backend():
        if shutil.which("docker"):
            try:
                r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                                   capture_output=True, timeout=5)
                if r.returncode == 0:
                    return ContainerBackend.DOCKER
            except (OSError, subprocess.SubprocessError):
                pass
        if shutil.which("podman"):
            return ContainerBackend.PODMAN
        return ContainerBackend.NONE

    @property
    def has_container_runtime(self):
        return self.backend != ContainerBackend.NONE

    @property
    def is_degraded(self):
        return self.backend == ContainerBackend.NONE

    def start_target(self, target, wait_ready=True):
        with self._lock:
            if not self.has_container_runtime:
                return self._create_simulated_target(target)
            if target.host_port == 0:
                target.host_port = self._allocate_port()
            try:
                info = self._docker_run(target, wait_ready)
                self._containers[target.name] = info
                self._save_state()
                return info
            except Exception as e:
                logger.error("Failed to start lab %s: %s", target.name, e)
                return self._create_simulated_target(target)

    def stop_target(self, name):
        with self._lock:
            info = self._containers.get(name)
            if info is None:
                return False
            if self.has_container_runtime and info.status == LabStatus.RUNNING:
                try:
                    subprocess.run([self.backend.value, "stop", info.container_id],
                                   capture_output=True, timeout=15)
                    subprocess.run([self.backend.value, "rm", info.container_id],
                                   capture_output=True, timeout=10)
                except (OSError, subprocess.SubprocessError):
                    pass
            self._used_ports.discard(info.host_port)
            del self._containers[name]
            self._save_state()
            return True

    def stop_all(self):
        with self._lock:
            for name in list(self._containers.keys()):
                self.stop_target(name)

    def get_target(self, name):
        return self._containers.get(name)

    def list_targets(self):
        return list(self._containers.values())

    @property
    def target_count(self):
        return len(self._containers)

    def health_check(self, name):
        info = self._containers.get(name)
        if info is None:
            return False
        if not self.has_container_runtime:
            return info.status == LabStatus.DEGRADED
        try:
            r = subprocess.run([self.backend.value, "inspect", "--format",
                               "{{.State.Running}}", info.container_id],
                              capture_output=True, timeout=5)
            return r.returncode == 0 and r.stdout.decode().strip().lower() == "true"
        except (OSError, subprocess.SubprocessError):
            return False

    def _docker_run(self, target, wait_ready):
        container_name = f"xuanjian-lab-{target.name}-{int(time.time())}"
        cmd = [self.backend.value, "run", "-d", "--name", container_name,
               "-p", f"127.0.0.1:{target.host_port}:{target.internal_port}",
               "--label", "xuanjian-lab=true", "--restart", "no"]
        for k, v in target.env_vars.items():
            cmd.extend(["-e", f"{k}={v}"])
        for k, v in target.labels.items():
            cmd.extend(["--label", f"{k}={v}"])
        if target.image:
            cmd.append(target.image)
        elif target.dockerfile_path:
            build_dir = Path(target.dockerfile_path).parent
            try:
                subprocess.run([self.backend.value, "build", "-t",
                               f"xuanjian-lab-{target.name}", str(build_dir)],
                              capture_output=True, timeout=target.timeout_seconds)
            except (OSError, subprocess.SubprocessError):
                pass
            cmd.append(f"xuanjian-lab-{target.name}")
        else:
            raise ValueError("Must specify image or dockerfile_path")
        r = subprocess.run(cmd, capture_output=True, timeout=target.timeout_seconds)
        if r.returncode != 0:
            raise RuntimeError(f"docker run failed: {r.stderr.decode(errors=\'replace\')[:200]}")
        container_id = r.stdout.decode().strip()
        now = datetime.now(timezone.utc).isoformat()
        health = "unknown"
        if wait_ready:
            ready = self._wait_healthy(port=target.host_port, timeout=target.timeout_seconds)
            health = "healthy" if ready else "unhealthy"
        return ContainerInfo(container_id=container_id, name=target.name,
                           status=LabStatus.RUNNING, host_port=target.host_port,
                           internal_port=target.internal_port,
                           image=target.image or f"xuanjian-lab-{target.name}",
                           created_at=now, started_at=now, health=health)

    def _wait_healthy(self, port, timeout=30):
        import socket
        start = time.time()
        while time.time() - start < timeout:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                r = s.connect_ex(("127.0.0.1", port))
                s.close()
                if r == 0:
                    return True
            except OSError:
                pass
            time.sleep(1)
        return False

    def _create_simulated_target(self, target):
        if target.host_port == 0:
            target.host_port = self._allocate_port()
        now = datetime.now(timezone.utc).isoformat()
        return ContainerInfo(container_id=f"simulated-{_uuid_mod.uuid4().hex[:8]}",
                           name=target.name, status=LabStatus.DEGRADED,
                           host_port=target.host_port, internal_port=target.internal_port,
                           image="simulated", created_at=now, started_at=now,
                           health="degraded")

    def _allocate_port(self):
        for port in range(self.PORT_RANGE_START, self.PORT_RANGE_END):
            if port not in self._used_ports:
                self._used_ports.add(port)
                return port
        import random
        return random.randint(20000, 30000)

    def _save_state(self):
        try:
            state = {"backend": self.backend.value, "containers": {}}
            for name, info in self._containers.items():
                state["containers"][name] = {
                    "container_id": info.container_id, "name": info.name,
                    "status": info.status.value, "host_port": info.host_port,
                    "internal_port": info.internal_port, "image": info.image,
                    "created_at": info.created_at, "health": info.health}
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            Path(self.state_file).write_text(json.dumps(state, indent=2), encoding="utf-8")
        except OSError:
            pass

    def _load_state(self):
        try:
            p = Path(self.state_file)
            if not p.exists():
                return
            state = json.loads(p.read_text(encoding="utf-8"))
            for name, data in state.get("containers", {}).items():
                self._containers[name] = ContainerInfo(
                    container_id=data["container_id"], name=data["name"],
                    status=LabStatus(data["status"]), host_port=data["host_port"],
                    internal_port=data["internal_port"], image=data["image"],
                    created_at=data.get("created_at", ""),
                    health=data.get("health", "unknown"))
                self._used_ports.add(data["host_port"])
        except (OSError, json.JSONDecodeError, KeyError):
            pass


# Preset target definitions
DEFAULT_TARGETS = {
    "python-vuln-app": LabTarget(
        name="python-vuln-app",
        dockerfile_path="target-lab-temp/playground/python-vuln-app",
        internal_port=5000, host_port=18080,
        labels={"type": "python", "vuln_level": "medium"}),
    "js-vuln-app": LabTarget(
        name="js-vuln-app",
        dockerfile_path="target-lab-temp/playground/js-vuln-app",
        internal_port=3000, host_port=18081,
        labels={"type": "javascript", "vuln_level": "medium"}),
    "php-lab": LabTarget(
        name="php-lab",
        dockerfile_path="target-lab-temp/lab_sources",
        internal_port=80, host_port=18082,
        labels={"type": "php", "vuln_level": "high"}),
    "java-deser-lab": LabTarget(
        name="java-deser-lab",
        dockerfile_path="target-lab-temp/lab_sources/java",
        internal_port=8080, host_port=18083,
        labels={"type": "java", "vuln_level": "critical"}),
}
'''

target_path = r"C:\Users\lenovo\xuanjian-ai\fp_sentinel\attack\v3_ai_pentest\lab_environment.py"
with open(target_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("OK:", len(content), "chars written to", target_path)
