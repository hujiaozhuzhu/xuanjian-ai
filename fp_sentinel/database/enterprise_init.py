"""
企业级功能统一初始化管理（v2.5.1 P1）

整合权限 / 任务 / 通知三大企业模块的 SQLite 数据库初始化，
提供一站式开箱即用的配置能力：
- 权限模块表（users / user_project_roles / audit_log / permission_definitions）
- 任务模块表（et_tasks / et_task_transitions / et_task_comments）
- 通知模块表（通过独立 NotifyStore 管理）
- 默认管理员账号（admin / 初始密码提示修改）

使用方式:
    await initialize_enterprise_database(db_path)
    # 一键初始化所有表 + 创建管理员账号
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Tuple

import aiosqlite

from ..enterprise_perm.models import PERM_SCHEMA_SQL, ROLE_PERMISSIONS
from ..enterprise_task.repository import TASK_SCHEMA_SQL
from ..devops.repository import SCHEMA_SQL as DEVOPS_SCHEMA_SQL
from ..notify.store import SCHEMA_SQL as NOTIFY_SCHEMA_SQL

logger = logging.getLogger(__name__)

# 默认管理员账号配置
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_DISPLAY_NAME = "系统管理员"

# 管理员初始化审计记录
_ADMIN_INIT_DETAIL = "{\"source\": \"enterprise_init\", \"note\": \"默认管理员账号（首次初始化）\"}"


async def _ensure_directory(db_path: str) -> None:
    """确保数据库文件所在目录存在"""
    directory = os.path.dirname(db_path)
    if directory:
        os.makedirs(directory, exist_ok=True)


async def _table_exists(conn: aiosqlite.Connection, table_name: str) -> bool:
    """检查表是否存在"""
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    )
    row = await cursor.fetchone()
    return row is not None


async def _user_count(conn: aiosqlite.Connection) -> int:
    """统计当前用户数量"""
    if not await _table_exists(conn, "users"):
        return 0
    cursor = await conn.execute("SELECT COUNT(*) FROM users")
    row = await cursor.fetchone()
    return int(row[0]) if row else 0


async def _seed_permission_definitions(conn: aiosqlite.Connection) -> None:
    """写入角色→权限映射到 permission_definitions 表"""
    # 检查是否已有数据（幂等）
    cursor = await conn.execute("SELECT COUNT(*) FROM permission_definitions")
    row = await cursor.fetchone()
    if row and int(row[0]) > 0:
        return

    from ..enterprise_perm.models import Permission, Role

    for role, perms in ROLE_PERMISSIONS.items():
        for perm in perms:
            await conn.execute(
                """INSERT OR IGNORE INTO permission_definitions (role, permission, description)
                   VALUES (?, ?, ?)""",
                (role.value, perm.value, f"{role.value} 默认拥有 {perm.value}"),
            )
    await conn.commit()
    logger.info("permission_definitions 已初始化 (%d 条角色权限映射)",
                sum(len(p) for p in ROLE_PERMISSIONS.values()))


async def create_default_admin(conn: aiosqlite.Connection) -> Tuple[Optional[str], bool]:
    """创建默认管理员账号

    Returns:
        (user_id, created): 用户ID 和 是否新创建（False 表示已存在）
    """
    import uuid
    from datetime import datetime, timezone

    # 检查 admin 是否已存在
    cursor = await conn.execute(
        "SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN_USERNAME,)
    )
    existing = await cursor.fetchone()
    if existing:
        logger.info("默认管理员账号 'admin' 已存在（ID: %s...）", str(existing[0])[:8])
        return str(existing[0]), False

    # 检查是否已有管理员（防重复）
    cursor = await conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    row = await cursor.fetchone()
    if row and int(row[0]) > 0:
        logger.info("已有管理员账号存在，跳过创建默认 admin")
        return None, False

    # 创建默认管理员
    admin_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await conn.execute(
        """INSERT INTO users (id, username, display_name, role, is_active, created_at, updated_at)
           VALUES (?, ?, ?, 'admin', 1, ?, ?)""",
        (admin_id, DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_DISPLAY_NAME, now, now),
    )
    # 记录审计
    await conn.execute(
        """INSERT INTO audit_log (user_id, username, action, resource_type, resource_id, result, details, ip_address)
           VALUES (?, ?, 'user.create', 'user', ?, 'success', ?, '127.0.0.1')""",
        (admin_id, DEFAULT_ADMIN_USERNAME, admin_id, _ADMIN_INIT_DETAIL),
    )
    await conn.commit()
    logger.info("已创建默认管理员账号: %s (ID: %s)", DEFAULT_ADMIN_USERNAME, admin_id[:8])
    return admin_id, True


async def initialize_enterprise_database(
    db_path: str = "~/.xuanjian/data.db",
    create_admin: bool = True,
    wal_mode: bool = True,
) -> dict:
    """一站式初始化企业级功能数据库

    创建所有必需表（主表 + 权限 + 任务），写入初始数据，
    创建默认管理员账号，让企业功能无需额外配置即可使用。

    Args:
        db_path: SQLite 数据库路径（~ 会自动展开）
        create_admin: 是否创建默认管理员账号
        wal_mode: 是否启用 WAL 模式

    Returns:
        {
            "status": "initialized" | "already_initialized",
            "db_path": str,
            "tables_created": List[str],
            "admin_created": bool,
            "admin_username": str | None,
            "admin_id": str | None,
        }
    """
    from .connection import SCHEMA_SQL as MAIN_SCHEMA_SQL

    db_path = os.path.expanduser(os.path.expandvars(db_path))
    await _ensure_directory(db_path)

    result = {
        "status": "initialized",
        "db_path": db_path,
        "tables_created": [],
        "admin_created": False,
        "admin_username": None,
        "admin_id": None,
    }

    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row
    try:
        if wal_mode:
            await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute("PRAGMA busy_timeout=5000")

        # 记录已存在的表
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        existing_tables = {row[0] for row in await cursor.fetchall()}
        had_users = "users" in existing_tables

        # 按顺序执行 schema（幂等，只增不改）
        schemas_to_apply = [
            ("main", MAIN_SCHEMA_SQL),
            ("perm", PERM_SCHEMA_SQL),
            ("task", TASK_SCHEMA_SQL),
            ("devops", DEVOPS_SCHEMA_SQL),
        ]
        for label, schema_sql in schemas_to_apply:
            await conn.executescript(schema_sql)
            logger.debug("Schema applied: %s", label)
        await conn.commit()

        # 新创建的表名（取关键表作为代表）
        key_main_tables = ["projects", "scan_history", "findings", "false_positive_marks"]
        key_perm_tables = ["users", "user_project_roles", "audit_log", "permission_definitions"]
        key_task_tables = ["et_tasks", "et_task_transitions", "et_task_comments"]
        key_devops_tables = [
            "do_finding_ticket_mapping",
            "do_sync_record",
            "do_pipeline_gate_record",
        ]

        for t in key_main_tables + key_perm_tables + key_task_tables + key_devops_tables:
            if t not in existing_tables:
                result["tables_created"].append(t)

        # 写入权限定义表初始数据
        await _seed_permission_definitions(conn)

        # 创建默认管理员
        if create_admin and not had_users:
            admin_id, created = await create_default_admin(conn)
            result["admin_created"] = created
            if created and admin_id:
                result["admin_id"] = admin_id
                result["admin_username"] = DEFAULT_ADMIN_USERNAME
        elif had_users:
            result["status"] = "already_initialized"
            logger.info("已有用户数据，跳过管理员创建")

        if result["tables_created"]:
            logger.info(
                "企业级数据库初始化完成: 新创建 %d 张表, 路径=%s",
                len(result["tables_created"]), db_path,
            )
        else:
            result["status"] = "already_initialized"
            logger.info("企业级数据库已初始化过，无需重复创建")

    finally:
        await conn.close()

    return result


async def initialize_all_enterprise_dbs(
    main_db_path: str = "~/.xuanjian/data.db",
    notify_db_path: str = "~/.xuanjian/notify.db",
) -> dict:
    """初始化所有企业功能数据库（主库 + 通知库）

    Args:
        main_db_path: 主数据库路径（含权限+任务+扫描）
        notify_db_path: 通知独立数据库路径

    Returns:
        包含两个数据库初始化结果的合并信息
    """
    # 初始化主库
    main_result = await initialize_enterprise_database(main_db_path, create_admin=True)

    # 初始化通知库（独立连接）
    notify_result = await _initialize_notify_db(notify_db_path)

    return {
        "main": main_result,
        "notify": notify_result,
    }


async def _initialize_notify_db(db_path: str) -> dict:
    """初始化通知模块独立数据库"""
    db_path = os.path.expanduser(os.path.expandvars(db_path))
    await _ensure_directory(db_path)

    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row
    try:
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.executescript(NOTIFY_SCHEMA_SQL)
        await conn.commit()
        logger.info("通知数据库初始化完成: %s", db_path)
        return {"status": "initialized", "db_path": db_path}
    finally:
        await conn.close()
