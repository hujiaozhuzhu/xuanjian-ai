"""
V3.0 AI Pentest - Lab Environment Tests
"""
import os
import tempfile
import pytest
from fp_sentinel.attack.v3_ai_pentest.lab_environment import (
    LabEnvironment,
    LabTarget,
    LabStatus,
    ContainerBackend,
    DEFAULT_TARGETS,
)


def _tmp_state():
    """Generate a unique temp state file path per test."""
    fd, path = tempfile.mkstemp(suffix=".json", prefix="lab_test_", dir=tempfile.gettempdir())
    os.close(fd)
    os.unlink(path)
    return path


class TestLabTarget:
    def test_default_construction(self):
        target = LabTarget(name="test")
        assert target.name == "test"
        assert target.internal_port == 80
        assert target.host_port == 0

    def test_custom_ports(self):
        target = LabTarget(name="test", internal_port=5000, host_port=18080)
        assert target.internal_port == 5000
        assert target.host_port == 18080


class TestLabEnvironment:
    def test_degraded_mode(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        assert lab.is_degraded
        assert not lab.has_container_runtime

    def test_simulated_target(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        target = LabTarget(name="test", internal_port=5000)
        info = lab.start_target(target, wait_ready=False)
        assert info.status == LabStatus.DEGRADED
        assert info.host_port >= 18080
        lab.stop_all()

    def test_allocate_port(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        port = lab._allocate_port()
        assert port >= LabEnvironment.PORT_RANGE_START
        assert port in lab._used_ports

    def test_port_reuse_on_stop(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        target = LabTarget(name="test1", internal_port=5000)
        info = lab.start_target(target, wait_ready=False)
        port = info.host_port
        lab.stop_target("test1")
        assert port not in lab._used_ports

    def test_get_target(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        target = LabTarget(name="test", internal_port=5000)
        lab.start_target(target, wait_ready=False)
        info = lab.get_target("test")
        assert info is not None
        assert info.name == "test"
        lab.stop_all()

    def test_list_targets(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        lab.start_target(LabTarget(name="t1"), wait_ready=False)
        lab.start_target(LabTarget(name="t2"), wait_ready=False)
        targets = lab.list_targets()
        assert len(targets) == 2
        lab.stop_all()

    def test_stop_all(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        lab.start_target(LabTarget(name="t1"), wait_ready=False)
        lab.start_target(LabTarget(name="t2"), wait_ready=False)
        lab.stop_all()
        assert lab.target_count == 0

    def test_health_check_nonexistent(self):
        lab = LabEnvironment(backend=ContainerBackend.NONE, state_file=_tmp_state())
        assert not lab.health_check("nonexistent")

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


class TestContainerBackend:
    def test_enum_values(self):
        assert ContainerBackend.DOCKER.value == "docker"
        assert ContainerBackend.PODMAN.value == "podman"
        assert ContainerBackend.NONE.value == "none"


class TestLabStatus:
    def test_status_enum(self):
        assert LabStatus.STOPPED.value == "stopped"
        assert LabStatus.RUNNING.value == "running"
        assert LabStatus.DEGRADED.value == "degraded"
