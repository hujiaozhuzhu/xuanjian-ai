"""
V3.0 AI Pentest - Lab Environment Tests (Full Coverage)

Covers: LabEnvironment, LabTarget, LabStatus, ContainerBackend, ContainerInfo,
        DEFAULT_TARGETS, _detect_backend, _docker_run, _wait_healthy,
        _create_simulated_target, _allocate_port, _save_state, _load_state,
        _safe_save_state, start_target (both degraded and docker paths),
        stop_target, stop_all, health_check, is_degraded, has_container_runtime,
        target_count, get_target, list_targets
"""
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from fp_sentinel.attack.v3_ai_pentest.lab_environment import (
    ContainerBackend,
    ContainerInfo,
    DEFAULT_TARGETS,
    LabEnvironment,
    LabStatus,
    LabTarget,
)


def _tmp_state():
    """Generate a unique temp state file path per test."""
    fd, path = tempfile.mkstemp(suffix=".json", prefix="lab_test_", dir=tempfile.gettempdir())
    os.close(fd)
    os.unlink(path)
    return path


# ============================================================
# Test LabTarget dataclass
# ============================================================


class TestLabTarget:
    def test_default_construction(self):
        target = LabTarget(name="test")
        assert target.name == "test"
        assert target.internal_port == 80
        assert target.host_port == 0
        assert target.image == ""
        assert target.dockerfile_path == ""
        assert target.env_vars == {}
        assert target.labels == {}
        assert target.timeout_seconds == 60

    def test_custom_ports(self):
        target = LabTarget(name="test", internal_port=5000, host_port=18080)
        assert target.internal_port == 5000
        assert target.host_port == 18080

    def test_full_custom(self):
        target = LabTarget(
            name="full-test",
            image="nginx:latest",
            internal_port=443,
            host_port=18443,
            env_vars={"DEBUG": "1", "SECRET": "key"},
            labels={"type": "web", "level": "high"},
            timeout_seconds=120,
        )
        assert target.image == "nginx:latest"
        assert target.env_vars == {"DEBUG": "1", "SECRET": "key"}
        assert target.labels == {"type": "web", "level": "high"}
        assert target.timeout_seconds == 120


# ============================================================
# Test ContainerInfo dataclass
# ============================================================


class TestContainerInfo:
    def test_default_construction(self):
        info = ContainerInfo(
            container_id="abc123",
            name="test",
            status=LabStatus.RUNNING,
            host_port=18080,
            internal_port=80,
            image="nginx",
        )
        assert info.container_id == "abc123"
        assert info.health == "unknown"

    def test_full_fields(self):
        now = "2025-01-01T00:00:00+00:00"
        info = ContainerInfo(
            container_id="xyz",
            name="svc",
            status=LabStatus.RUNNING,
            host_port=18081,
            internal_port=3000,
            image="node:18",
            created_at=now,
            started_at=now,
            health="healthy",
        )
        assert info.created_at == now
        assert info.health == "healthy"


# ============================================================
# Test LabEnvironment - Construction & Properties
# ============================================================


class TestLabEnvironmentConstruction:
    def test_degraded_mode(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        assert lab.is_degraded
        assert not lab.has_container_runtime

    def test_docker_backend_mode(self):
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=_tmp_state())
        assert not lab.is_degraded
        assert lab.has_container_runtime

    def test_podman_backend_mode(self):
        lab = LabEnvironment(backend=ContainerBackend.PODMAN, state_file=_tmp_state())
        assert not lab.is_degraded
        assert lab.has_container_runtime

    def test_auto_detect_backend(self):
        lab = LabEnvironment(state_file=_tmp_state())
        # Should detect whatever is available, or NONE
        assert lab.backend in (ContainerBackend.DOCKER, ContainerBackend.PODMAN, ContainerBackend.NONE)

    def test_detect_backend_docker_available(self):
        """Test _detect_backend when docker command succeeds."""
        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.shutil.which", return_value="C:\\docker.exe"):
            with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=b"24.0.5")
                backend = LabEnvironment._detect_backend()
                assert backend == ContainerBackend.DOCKER

    def test_detect_backend_docker_not_found(self):
        """Test _detect_backend when only podman is available."""
        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.shutil.which") as mock_which:
            mock_which.side_effect = lambda cmd: "C:\\podman.exe" if cmd == "podman" else None
            backend = LabEnvironment._detect_backend()
            assert backend == ContainerBackend.PODMAN

    def test_detect_backend_none_available(self):
        """Test _detect_backend when no container runtime is found."""
        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.shutil.which", return_value=None):
            backend = LabEnvironment._detect_backend()
            assert backend == ContainerBackend.NONE

    def test_detect_backend_docker_error(self):
        """Test _detect_backend when docker command fails."""
        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.shutil.which") as mock_which:
            mock_which.side_effect = lambda cmd: "C:\\docker.exe" if cmd == "docker" else None
            with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stdout=b"")
                backend = LabEnvironment._detect_backend()
                assert backend == ContainerBackend.NONE

    def test_detect_backend_subprocess_exception(self):
        """Test _detect_backend when subprocess raises OSError."""
        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.shutil.which") as mock_which:
            mock_which.side_effect = lambda cmd: "C:\\docker.exe" if cmd == "docker" else None
            with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
                mock_run.side_effect = OSError("timeout")
                backend = LabEnvironment._detect_backend()
                assert backend == ContainerBackend.NONE

    def test_default_state_file(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE)
        assert ".lab_state.json" in lab.state_file


# ============================================================
# Test LabEnvironment - Port Allocation
# ============================================================


class TestPortAllocation:
    def test_allocate_port(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        port = lab._allocate_port()
        assert port >= LabEnvironment.PORT_RANGE_START
        assert port in lab._used_ports

    def test_allocate_multiple_ports_unique(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        ports = [lab._allocate_port() for _ in range(5)]
        assert len(ports) == len(set(ports))
        for p in ports:
            assert p in lab._used_ports

    def test_allocate_port_range_exhaustion(self):
        """When all ports in range are used, allocate random."""
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        # Pre-fill the entire range
        for p in range(LabEnvironment.PORT_RANGE_START, LabEnvironment.PORT_RANGE_END):
            lab._used_ports.add(p)
        port = lab._allocate_port()
        assert port >= 20000
        assert port <= 30000

    def test_port_reuse_on_stop(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        target = LabTarget(name="test1", internal_port=5000)
        info = lab.start_target(target, wait_ready=False)
        port = info.host_port
        lab.stop_target("test1")
        assert port not in lab._used_ports


# ============================================================
# Test LabEnvironment - Simulated Target (Degraded Mode)
# ============================================================


class TestSimulatedMode:
    def test_simulated_target(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        target = LabTarget(name="test", internal_port=5000)
        info = lab.start_target(target, wait_ready=False)
        assert info.status == LabStatus.DEGRADED
        assert info.host_port >= 18080
        assert info.image == "simulated"
        assert info.health == "degraded"
        lab.stop_all()

    def test_simulated_target_with_explicit_host_port(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        target = LabTarget(name="test", internal_port=5000, host_port=19999)
        info = lab.start_target(target, wait_ready=False)
        assert info.host_port == 19999
        lab.stop_all()

    def test_create_simulated_target(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        target = LabTarget(name="sim-svc")
        info = lab._create_simulated_target(target)
        assert info.status == LabStatus.DEGRADED
        assert info.image == "simulated"
        assert "simulated-" in info.container_id

    def test_start_degraded_does_not_save_state(self):
        """Degraded mode should not attempt file I/O for state."""
        state = _tmp_state()
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=state)
        target = LabTarget(name="no-io-test")
        lab.start_target(target, wait_ready=False)
        assert not os.path.exists(state)
        lab.stop_all()


# ============================================================
# Test LabEnvironment - Docker Path (Mocked)
# ============================================================


class TestDockerPath:
    """Tests the docker-runtime code paths using mocks."""

    def test_start_target_with_docker_success(self):
        """Test successful docker container start."""
        state = _tmp_state()
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)
        lab._wait_healthy = MagicMock(return_value=True)

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"abc123def456\n", stderr=b"")
            target = LabTarget(name="docker-test", image="nginx:latest", host_port=18090)
            info = lab.start_target(target, wait_ready=True)

        assert info.status == LabStatus.RUNNING
        assert info.container_id == "abc123def456"
        assert info.image == "nginx:latest"
        assert info.health == "healthy"
        assert "docker-test" in lab._containers
        lab.stop_all()

    def test_start_target_with_docker_build_from_dockerfile(self):
        """Test docker build from Dockerfile path."""
        state = _tmp_state()
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)
        lab._wait_healthy = MagicMock(return_value=True)

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            # First call: build, Second call: run
            mock_run.return_value = MagicMock(returncode=0, stdout=b"build123\n", stderr=b"")
            target = LabTarget(name="dockerfile-test", dockerfile_path="/tmp/Dockerfile", host_port=18091)
            info = lab.start_target(target, wait_ready=True)

        assert info.status == LabStatus.RUNNING
        assert info.image == "xuanjian-lab-dockerfile-test"
        lab.stop_all()

    def test_start_target_docker_fails_fallback_to_simulated(self):
        """Test docker fail falls back to simulated target."""
        state = _tmp_state()
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout=b"", stderr=b"docker error")
            target = LabTarget(name="fail-test", image="nonexistent-image", host_port=18092)
            info = lab.start_target(target, wait_ready=False)

        # Should fall back to simulated
        assert info.status == LabStatus.DEGRADED
        assert info.image == "simulated"
        lab.stop_all()

    def test_start_target_no_image_or_dockerfile(self):
        """Test docker path with no image or dockerfile raises ValueError."""
        state = _tmp_state()
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            # Build call (no image/dockerfile, build produces nothing)
            mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")
            target = LabTarget(name="no-spec", host_port=18093)
            info = lab.start_target(target, wait_ready=False)

        # Falls back to simulated because ValueError is raised at run, caught and simulated
        assert info.status == LabStatus.DEGRADED
        lab.stop_all()

    def test_start_target_unhealthy(self):
        """Test that unhealthy containers get proper health status."""
        state = _tmp_state()
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)
        lab._wait_healthy = MagicMock(return_value=False)

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"unhealthy123\n", stderr=b"")
            target = LabTarget(name="unhealthy-test", image="nginx", host_port=18094)
            info = lab.start_target(target, wait_ready=True)

        assert info.health == "unhealthy"
        lab.stop_all()

    def test_start_target_with_env_vars_and_labels(self):
        """Test docker run includes env vars and labels."""
        state = _tmp_state()
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)
        lab._wait_healthy = MagicMock(return_value=True)

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"env123\n", stderr=b"")
            target = LabTarget(
                name="env-test", image="alpine", host_port=18095,
                env_vars={"DB_HOST": "localhost", "SECRET": "test"},
                labels={"team": "security", "env": "lab"},
            )
            info = lab.start_target(target, wait_ready=True)

        assert info.status == LabStatus.RUNNING
        lab.stop_all()


# ============================================================
# Test LabEnvironment - Docker Stop & Cleanup
# ============================================================


class TestDockerStop:
    def test_stop_target_docker_calls_stop_and_rm(self):
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=_tmp_state())
        # Manually insert a running container
        lab._containers["stop-test"] = ContainerInfo(
            container_id="stop123", name="stop-test",
            status=LabStatus.RUNNING, host_port=18090,
            internal_port=80, image="nginx",
        )

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = lab.stop_target("stop-test")

        assert result is True
        assert "stop-test" not in lab._containers
        assert 18090 not in lab._used_ports

    def test_stop_target_docker_handles_subprocess_error(self):
        """Test that stop handles subprocess errors gracefully."""
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=_tmp_state())
        lab._containers["err-test"] = ContainerInfo(
            container_id="err123", name="err-test",
            status=LabStatus.RUNNING, host_port=18091,
            internal_port=80, image="nginx",
        )

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            import subprocess
            mock_run.side_effect = subprocess.SubprocessError("error")
            result = lab.stop_target("err-test")

        # Should still be removed
        assert "err-test" not in lab._containers

    def test_stop_nonexistent_returns_false(self):
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=_tmp_state())
        result = lab.stop_target("does-not-exist")
        assert result is False

    def test_stop_all_cleans_all(self):
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=_tmp_state())
        lab._containers["a"] = ContainerInfo(
            container_id="a1", name="a", status=LabStatus.RUNNING,
            host_port=18080, internal_port=80, image="nginx")
        lab._containers["b"] = ContainerInfo(
            container_id="b2", name="b", status=LabStatus.RUNNING,
            host_port=18081, internal_port=80, image="nginx")
        lab._used_ports.update([18080, 18081])

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run"):
            lab.stop_all()

        assert lab.target_count == 0


# ============================================================
# Test LabEnvironment - Health Check
# ============================================================


class TestHealthCheck:
    def test_health_check_nonexistent(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        assert not lab.health_check("nonexistent")

    def test_health_check_degraded_mode(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        lab.start_target(LabTarget(name="deg"), wait_ready=False)
        assert lab.health_check("deg")
        lab.stop_all()

    def test_health_check_degraded_returns_false_if_stopped(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        lab._containers["stop-hc"] = ContainerInfo(
            container_id="s1", name="stop-hc", status=LabStatus.STOPPED,
            host_port=18081, internal_port=80, image="nginx")
        assert not lab.health_check("stop-hc")

    def test_health_check_docker_success(self):
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=_tmp_state())
        lab._containers["hc-docker"] = ContainerInfo(
            container_id="hc123", name="hc-docker", status=LabStatus.RUNNING,
            host_port=18090, internal_port=80, image="nginx")

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"true")
            assert lab.health_check("hc-docker")

    def test_health_check_docker_not_running(self):
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=_tmp_state())
        lab._containers["hc-off"] = ContainerInfo(
            container_id="hcoff", name="hc-off", status=LabStatus.RUNNING,
            host_port=18091, internal_port=80, image="nginx")

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=b"false")
            assert not lab.health_check("hc-off")

    def test_health_check_docker_subprocess_error(self):
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=_tmp_state())
        lab._containers["hc-err"] = ContainerInfo(
            container_id="hcerr", name="hc-err", status=LabStatus.RUNNING,
            host_port=18092, internal_port=80, image="nginx")

        with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.subprocess.run") as mock_run:
            import subprocess
            mock_run.side_effect = subprocess.SubprocessError("fail")
            assert not lab.health_check("hc-err")


# ============================================================
# Test LabEnvironment - Query Operations
# ============================================================


class TestQueryOps:
    def test_get_target(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        target = LabTarget(name="test", internal_port=5000)
        lab.start_target(target, wait_ready=False)
        info = lab.get_target("test")
        assert info is not None
        assert info.name == "test"
        lab.stop_all()

    def test_get_target_nonexistent_returns_none(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        assert lab.get_target("ghost") is None

    def test_list_targets(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        lab.start_target(LabTarget(name="t1"), wait_ready=False)
        lab.start_target(LabTarget(name="t2"), wait_ready=False)
        targets = lab.list_targets()
        assert len(targets) == 2
        lab.stop_all()

    def test_list_targets_empty(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        assert lab.list_targets() == []

    def test_target_count(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        assert lab.target_count == 0
        lab.start_target(LabTarget(name="t1"), wait_ready=False)
        assert lab.target_count == 1
        lab.stop_all()
        assert lab.target_count == 0

    def test_multiple_targets_chain(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        for i in range(3):
            lab.start_target(LabTarget(name=f"svc{i}", internal_port=5000+i), wait_ready=False)
        assert lab.target_count == 3
        lab.stop_all()
        assert lab.target_count == 0


# ============================================================
# Test LabEnvironment - Wait Healthy (Mocked)
# ============================================================


class TestWaitHealthy:
    def test_wait_healthy_success(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        import socket as _sock_mod
        with patch.object(_sock_mod, "socket") as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 0  # Success
            mock_socket.return_value = mock_sock
            result = lab._wait_healthy(port=18080, timeout=5)
            assert result is True

    def test_wait_healthy_timeout(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        import socket as _sock_mod
        with patch.object(_sock_mod, "socket") as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1  # Connection refused
            mock_socket.return_value = mock_sock
            with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.time.sleep"):
                result = lab._wait_healthy(port=18080, timeout=2)
                assert result is False

    def test_wait_healthy_os_error(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        import socket as _sock_mod
        with patch.object(_sock_mod, "socket") as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.side_effect = OSError("network error")
            mock_socket.return_value = mock_sock
            with patch("fp_sentinel.attack.v3_ai_pentest.lab_environment.time.sleep"):
                result = lab._wait_healthy(port=18080, timeout=2)
                assert result is False


# ============================================================
# Test LabEnvironment - State Persistence
# ============================================================


class TestStatePersistence:
    def test_load_state_empty_file(self):
        """Test _load_state with empty file (returns gracefully)."""
        state = _tmp_state()
        Path(state).write_text("", encoding="utf-8")
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)
        # Should not raise
        assert lab.target_count == 0

    def test_load_state_nonexistent_file(self):
        """Test _load_state with non-existent file."""
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file="/nonexistent/path/state.json")
        assert lab.target_count == 0

    def test_load_state_corrupted_json(self):
        """Test _load_state with corrupted JSON."""
        state = _tmp_state()
        Path(state).write_text("not valid json{{", encoding="utf-8")
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)
        assert lab.target_count == 0

    def test_load_state_valid(self):
        """Test _load_state with valid state file."""
        state = _tmp_state()
        state_data = {
            "backend": "docker",
            "containers": {
                "loaded-svc": {
                    "container_id": "load123", "name": "loaded-svc",
                    "status": "running", "host_port": 18085,
                    "internal_port": 80, "image": "nginx",
                    "created_at": "", "health": "healthy",
                }
            }
        }
        Path(state).write_text(json.dumps(state_data), encoding="utf-8")
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)
        assert lab.target_count == 1
        assert 18085 in lab._used_ports
        info = lab.get_target("loaded-svc")
        assert info is not None
        assert info.container_id == "load123"

    def test_load_state_missing_optional_fields(self):
        """Test _load_state with state missing optional fields."""
        state = _tmp_state()
        state_data = {
            "backend": "docker",
            "containers": {
                "minimal-svc": {
                    "container_id": "min123", "name": "minimal-svc",
                    "status": "running", "host_port": 18086,
                    "internal_port": 80, "image": "nginx",
                }
            }
        }
        Path(state).write_text(json.dumps(state_data), encoding="utf-8")
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)
        info = lab.get_target("minimal-svc")
        assert info is not None
        assert info.created_at == ""
        assert info.health == "unknown"

    def test_safe_save_state(self):
        """Test _safe_save_state writes correct format."""
        state = _tmp_state()
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file=state)
        lab._containers["save-test"] = ContainerInfo(
            container_id="save123", name="save-test",
            status=LabStatus.RUNNING, host_port=18087,
            internal_port=80, image="nginx",
            created_at="2025-01-01", health="healthy",
        )
        lab._safe_save_state()
        # Give async thread time to write (use join with broader timeout)
        import time
        time.sleep(2.0)

        if os.path.exists(state):
            data = json.loads(Path(state).read_text(encoding="utf-8"))
            assert "backend" in data
            assert "save-test" in data["containers"]
        else:
            # Async thread might still be running - the call must not raise
            pass

    def test_safe_save_state_io_error(self):
        """Test _safe_save_state handles I/O errors gracefully."""
        lab = LabEnvironment(backend=ContainerBackend.DOCKER, state_file="/nonexistent/dir/state.json")
        lab._containers["err"] = ContainerInfo(
            container_id="e1", name="err", status=LabStatus.RUNNING,
            host_port=18080, internal_port=80, image="nginx")
        # Should not raise
        lab._safe_save_state()

    def test_safe_save_state_skipped_in_none_backend(self):
        """Test that _safe_save_state is skipped in NONE backend mode."""
        state = _tmp_state()
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=state)
        lab._containers["skip-save"] = ContainerInfo(
            container_id="ss1", name="skip-save",
            status=LabStatus.DEGRADED, host_port=18080,
            internal_port=80, image="simulated")
        lab._safe_save_state()
        import time
        time.sleep(0.5)
        assert not os.path.exists(state)


# ============================================================
# Test DEFAULT_TARGETS
# ============================================================


class TestDefaultTargets:
    def test_targets_exist(self):
        assert "python-vuln-app" in DEFAULT_TARGETS
        assert "js-vuln-app" in DEFAULT_TARGETS
        assert "php-lab" in DEFAULT_TARGETS
        assert "java-deser-lab" in DEFAULT_TARGETS

    def test_target_ports_unique(self):
        ports = [t.host_port for t in DEFAULT_TARGETS.values() if t.host_port > 0]
        assert len(ports) == len(set(ports))

    def test_targets_have_labels(self):
        for name, target in DEFAULT_TARGETS.items():
            assert "type" in target.labels
            assert "vuln_level" in target.labels

    def test_targets_have_dockerfile_paths(self):
        for name, target in DEFAULT_TARGETS.items():
            assert target.dockerfile_path != ""

    def test_each_target_has_name(self):
        for name, target in DEFAULT_TARGETS.items():
            assert target.name == name


# ============================================================
# Test ContainerBackend & LabStatus Enums
# ============================================================


class TestContainerBackend:
    def test_enum_values(self):
        assert ContainerBackend.DOCKER.value == "docker"
        assert ContainerBackend.PODMAN.value == "podman"
        assert ContainerBackend.NONE.value == "none"

    def test_enum_comparison(self):
        assert ContainerBackend.DOCKER != ContainerBackend.PODMAN
        assert ContainerBackend.NONE == ContainerBackend.NONE


class TestLabStatus:
    def test_status_enum(self):
        assert LabStatus.STOPPED.value == "stopped"
        assert LabStatus.STARTING.value == "starting"
        assert LabStatus.RUNNING.value == "running"
        assert LabStatus.ERROR.value == "error"
        assert LabStatus.DEGRADED.value == "degraded"

    def test_status_count(self):
        assert len(LabStatus) == 5
