"""
对抗循环状态持久化

SQLite存储对抗循环的每轮结果，支持断点续跑和历史分析
"""

import json
import sqlite3
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class AdversarialStateStore:
    """对抗循环状态持久化存储"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = str(Path.home() / ".xuanjian" / "adversarial.db")

        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """初始化数据库"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS rounds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    round_num INTEGER,
                    detection_rate REAL,
                    false_positive_rate REAL,
                    bypass_rate_l3 REAL,
                    bypass_rate_l4 REAL,
                    total_cases INTEGER,
                    detected_cases INTEGER,
                    missed_cases INTEGER,
                    llm_calls INTEGER DEFAULT 0,
                    converged BOOLEAN DEFAULT 0,
                    fix_applied BOOLEAN DEFAULT 0,
                    fix_details TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS bypasses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    round_id INTEGER REFERENCES rounds(id),
                    rule_id TEXT,
                    difficulty TEXT,
                    strategy TEXT,
                    bypass_code TEXT,
                    detected BOOLEAN,
                    expected_detected BOOLEAN,
                    fix_applied BOOLEAN DEFAULT 0,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS adversarial_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT UNIQUE,
                    config_snapshot TEXT,
                    best_detection_rate REAL DEFAULT 0,
                    best_false_positive_rate REAL DEFAULT 1,
                    total_rounds INTEGER DEFAULT 0,
                    total_llm_calls INTEGER DEFAULT 0,
                    last_converged BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_rounds_rule ON rounds(rule_id);
                CREATE INDEX IF NOT EXISTS idx_bypasses_rule ON bypasses(rule_id);
                CREATE INDEX IF NOT EXISTS idx_bypasses_round ON bypasses(round_id);
            """)

    def save_round(
        self,
        rule_id: str,
        round_num: int,
        detection_rate: float,
        false_positive_rate: float = 0,
        bypass_rate_l3: float = 0,
        bypass_rate_l4: float = 0,
        total_cases: int = 0,
        detected_cases: int = 0,
        missed_cases: int = 0,
        llm_calls: int = 0,
        converged: bool = False,
        fix_applied: bool = False,
        fix_details: Dict = None,
        bypass_cases: List[Dict] = None,
    ) -> int:
        """保存一轮结果"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO rounds (
                    rule_id, round_num, detection_rate, false_positive_rate,
                    bypass_rate_l3, bypass_rate_l4, total_cases, detected_cases,
                    missed_cases, llm_calls, converged, fix_applied, fix_details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_id, round_num, detection_rate, false_positive_rate,
                bypass_rate_l3, bypass_rate_l4, total_cases, detected_cases,
                missed_cases, llm_calls, converged, fix_applied,
                json.dumps(fix_details) if fix_details else None,
            ))
            round_id = cursor.lastrowid

            # 保存绕过用例
            if bypass_cases:
                for case in bypass_cases:
                    conn.execute("""
                        INSERT INTO bypasses (
                            round_id, rule_id, difficulty, strategy,
                            bypass_code, detected, expected_detected
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        round_id, rule_id,
                        case.get("difficulty", ""),
                        case.get("strategy", ""),
                        case.get("bypass_code", ""),
                        case.get("detected", False),
                        case.get("expected_detected", True),
                    ))

            # 更新历史
            conn.execute("""
                INSERT INTO adversarial_history (rule_id, best_detection_rate, total_rounds, last_converged, updated_at)
                VALUES (?, ?, 1, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(rule_id) DO UPDATE SET
                    best_detection_rate = MAX(best_detection_rate, ?),
                    total_rounds = total_rounds + 1,
                    last_converged = ?,
                    updated_at = CURRENT_TIMESTAMP
            """, (rule_id, detection_rate, converged, detection_rate, converged))

            return round_id

    def load_latest(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """加载最新一轮结果"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT * FROM rounds WHERE rule_id = ?
                ORDER BY round_num DESC LIMIT 1
            """, (rule_id,)).fetchone()

            if row:
                return dict(row)
        return None

    def get_history(self, rule_id: str) -> List[Dict[str, Any]]:
        """获取规则的完整历史"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM rounds WHERE rule_id = ?
                ORDER BY round_num ASC
            """, (rule_id,)).fetchall()
            return [dict(r) for r in rows]

    def get_best_result(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """获取最佳结果"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("""
                SELECT * FROM rounds WHERE rule_id = ?
                ORDER BY detection_rate DESC LIMIT 1
            """, (rule_id,)).fetchone()

            if row:
                return dict(row)
        return None

    def get_convergence_history(self, rule_id: str, window: int = 3) -> List[Dict]:
        """获取最近N轮结果（用于收敛判定）"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM rounds WHERE rule_id = ?
                ORDER BY round_num DESC LIMIT ?
            """, (rule_id, window)).fetchall()
            return [dict(r) for r in reversed(rows)]

    def get_statistics(self) -> Dict[str, Any]:
        """获取全局统计"""
        with sqlite3.connect(self.db_path) as conn:
            total_rules = conn.execute(
                "SELECT COUNT(DISTINCT rule_id) FROM rounds"
            ).fetchone()[0]
            total_rounds = conn.execute(
                "SELECT COUNT(*) FROM rounds"
            ).fetchone()[0]
            converged_count = conn.execute(
                "SELECT COUNT(*) FROM adversarial_history WHERE last_converged = 1"
            ).fetchone()[0]
            avg_detection = conn.execute(
                "SELECT AVG(best_detection_rate) FROM adversarial_history"
            ).fetchone()[0] or 0

            return {
                "total_rules_tested": total_rules,
                "total_rounds": total_rounds,
                "converged_rules": converged_count,
                "average_detection_rate": round(avg_detection, 4),
            }

    def clear(self, rule_id: str = None):
        """清除数据"""
        with sqlite3.connect(self.db_path) as conn:
            if rule_id:
                conn.execute("DELETE FROM bypasses WHERE rule_id = ?", (rule_id,))
                conn.execute("DELETE FROM rounds WHERE rule_id = ?", (rule_id,))
                conn.execute("DELETE FROM adversarial_history WHERE rule_id = ?", (rule_id,))
            else:
                conn.execute("DELETE FROM bypasses")
                conn.execute("DELETE FROM rounds")
                conn.execute("DELETE FROM adversarial_history")
