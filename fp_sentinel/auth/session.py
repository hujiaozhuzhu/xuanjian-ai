"""
Session Persistence Engine

Provides encrypted local storage for authenticated sessions.
Supports save/load/clear with automatic expiry checking.

Security:
- S4: Session data is encrypted at rest (XOR cipher with machine-derived key)
- Credentials are NEVER stored - only session tokens
- All session data stays on local machine
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import (
    AuthSessionConfig,
    SessionState,
)

logger = logging.getLogger(__name__)


class SessionStore:
    """Encrypted local session storage."""

    DEFAULT_STORE_PATH = ".xuanjian_sessions"
    ENCRYPTION_MARKER = "XJENC1"

    def __init__(self, store_dir: Optional[str] = None):
        self._store_dir = Path(store_dir or self.DEFAULT_STORE_PATH)
        try:
            self._store_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self._store_dir = Path(".")
        self._lock = threading.Lock()
        self._cache: Dict[str, AuthSessionConfig] = {}
        self._derive_key()

    def _derive_key(self) -> None:
        try:
            login_name = os.getlogin()
        except (OSError, AttributeError):
            login_name = "default"
        machine_id = f"{os.name}-{login_name}-{os.getcwd()}"
        self._key = hashlib.sha256(machine_id.encode()).digest()

    def _encrypt(self, data: str) -> str:
        key = self._key
        encrypted = bytearray()
        for i, ch in enumerate(data.encode("utf-8")):
            encrypted.append(ch ^ key[i % len(key)])
        import base64
        return self.ENCRYPTION_MARKER + base64.b64encode(bytes(encrypted)).decode()

    def _decrypt(self, data: str) -> str:
        if not data.startswith(self.ENCRYPTION_MARKER):
            raise ValueError("Invalid session data format")
        import base64
        raw = base64.b64decode(data[len(self.ENCRYPTION_MARKER):])
        key = self._key
        decrypted = bytearray()
        for i, b in enumerate(raw):
            decrypted.append(b ^ key[i % len(key)])
        return bytes(decrypted).decode("utf-8")

    def _session_file(self, session_id: str) -> Path:
        return self._store_dir / f"{session_id}.json"

    def save(self, session: AuthSessionConfig) -> bool:
        with self._lock:
            try:
                data = session.model_dump_json()
                encrypted = self._encrypt(data)
                self._session_file(session.session_id).write_text(
                    encrypted, encoding="utf-8"
                )
                self._cache[session.session_id] = session
                return True
            except Exception as e:
                logger.warning(f"Failed to save session {session.session_id}: {e}")
                return False

    def load(self, session_id: str) -> Optional[AuthSessionConfig]:
        if session_id in self._cache:
            session = self._cache[session_id]
            if self._is_expired(session):
                self._cache.pop(session_id, None)
                return None
            return session
        try:
            file_path = self._session_file(session_id)
            if not file_path.exists():
                return None
            encrypted = file_path.read_text(encoding="utf-8")
            data = self._decrypt(encrypted)
            session = AuthSessionConfig(**json.loads(data))
            if self._is_expired(session):
                return None
            self._cache[session_id] = session
            return session
        except Exception as e:
            logger.warning(f"Failed to load session {session_id}: {e}")
            return None

    def list_sessions(self) -> List[str]:
        sessions = []
        try:
            for f in self._store_dir.glob("*.json"):
                sessions.append(f.stem)
        except OSError:
            pass
        return sessions

    def list_active_sessions(self) -> List[str]:
        return [sid for sid in self.list_sessions() if self.load(sid) is not None]

    def delete(self, session_id: str) -> bool:
        with self._lock:
            self._cache.pop(session_id, None)
            try:
                file_path = self._session_file(session_id)
                if file_path.exists():
                    file_path.unlink()
                return True
            except OSError:
                return False

    def clear_all(self) -> int:
        with self._lock:
            count = 0
            for sid in self.list_sessions():
                if self.delete(sid):
                    count += 1
            return count

    def cleanup_expired(self) -> int:
        count = 0
        for sid in self.list_sessions():
            if self.load(sid) is None:
                if self.delete(sid):
                    count += 1
        return count

    @staticmethod
    def _is_expired(session: AuthSessionConfig) -> bool:
        if session.expires_at is None:
            return False
        try:
            exp = datetime.fromisoformat(session.expires_at)
            return datetime.now(timezone.utc) > exp
        except (ValueError, TypeError):
            return False


class AuthSession:
    """High-level authenticated session manager."""

    def __init__(
        self,
        store: Optional[SessionStore] = None,
        session_id: Optional[str] = None,
    ):
        self._store = store or SessionStore()
        self._session_id = session_id or f"auth-{uuid.uuid4().hex[:8]}"
        self._config: Optional[AuthSessionConfig] = None
        self._state = SessionState.INITIAL
        self._login_time: Optional[str] = None

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def is_authenticated(self) -> bool:
        return self._state == SessionState.AUTHENTICATED and self._config is not None

    @property
    def config(self) -> Optional[AuthSessionConfig]:
        return self._config

    def init_session(
        self,
        base_url: str,
        cookies: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None,
        bearer_token: str = "",
        ttl_minutes: int = 30,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuthSessionConfig:
        """Initialize a new authenticated session config."""
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(minutes=ttl_minutes)).isoformat()
        # Use locals() to safely pass the bearer_token parameter
        bt = bearer_token
        self._config = AuthSessionConfig(
            session_id=self._session_id,
            base_url=base_url,
            cookies=cookies or [],
            headers=headers or {},
            bearer_token=bt,
            created_at=now.isoformat(),
            expires_at=expires_at,
            is_active=True,
            metadata=metadata or {},
        )
        self._state = SessionState.AUTHENTICATED
        self._login_time = now.isoformat()
        self._store.save(self._config)
        return self._config

    def load_session(self) -> Optional[AuthSessionConfig]:
        """Load session from store."""
        self._config = self._store.load(self._session_id)
        if self._config is None:
            self._state = SessionState.FAILED
            return None
        self._state = SessionState.AUTHENTICATED
        return self._config

    def refresh(self, ttl_minutes: int = 30) -> bool:
        """Refresh session expiry."""
        if self._config is None:
            return False
        now = datetime.now(timezone.utc)
        self._config.expires_at = (now + timedelta(minutes=ttl_minutes)).isoformat()
        self._config.is_active = True
        return self._store.save(self._config)

    def invalidate(self) -> None:
        """Mark session as logged out."""
        self._state = SessionState.LOGGED_OUT
        if self._config:
            self._config.is_active = False
            self._store.save(self._config)

    def get_auth_headers(self) -> Dict[str, str]:
        """Get headers needed for authenticated requests."""
        if not self._config:
            return {}
        headers = dict(self._config.headers)
        if self._config.bearer_token:
            headers["Authorization"] = "Bearer " + self._config.bearer_token
        return headers

    def get_cookie_header(self) -> str:
        """Build Cookie header from session cookies."""
        if not self._config:
            return ""
        parts = []
        for c in self._config.cookies:
            name = c.get("name", "")
            value = c.get("value", "")
            if name:
                parts.append(f"{name}={value}")
        return "; ".join(parts)

    def extend_cookies(self, new_cookies: List[Dict[str, Any]]) -> None:
        """Merge new cookies into session."""
        if not self._config:
            return
        existing = {c.get("name"): c for c in self._config.cookies}
        for nc in new_cookies:
            name = nc.get("name")
            if name:
                existing[name] = nc
        self._config.cookies = list(existing.values())
        self._store.save(self._config)

    def destroy(self) -> bool:
        """Permanently delete session."""
        return self._store.delete(self._session_id)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict (safe for reporting - no credentials)."""
        cfg = self._config
        has_token = bool(cfg and cfg.bearer_token)
        return {
            "session_id": self._session_id,
            "state": self._state.value,
            "is_authenticated": self.is_authenticated,
            "login_time": self._login_time,
            "base_url": cfg.base_url if cfg else "",
            "has_bearer_token": has_token,
            "cookie_count": len(cfg.cookies) if cfg else 0,
        }
