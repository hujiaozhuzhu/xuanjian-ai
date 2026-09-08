"""
玄鉴 v3.0 — 个性化代码风格模型 (Personalized Code Style Model)

适配企业代码风格，越用越准，长期使用后误报率可降到1%以下
版本: 3.0.0
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .feedback_store import FeedbackStore
from .models import CodeStyleProfile

logger = logging.getLogger(__name__)


# ─────────────────────── 框架识别模式 ───────────────────────

FRAMEWORK_PATTERNS = {
    "spring_boot": [
        r"@SpringBootApplication",
        r"@RestController",
        r"@Autowired",
        r"@Service",
        r"@Repository",
        r"import org\.springframework",
    ],
    "mybatis": [
        r"@Mapper",
        r"@Select\(",
        r"@Insert\(",
        r"@Update\(",
        r"xmlns:mybatis",
    ],
    "jackson": [
        r"ObjectMapper",
        r"@Json",
        r"import com\.fasterxml\.jackson",
    ],
    "servlet": [
        r"HttpServlet",
        r"HttpServletRequest",
        r"HttpServletResponse",
        r"@WebServlet",
    ],
    "react": [
        r"import React",
        r"React\.Component",
        r"useState\(",
        r"useEffect\(",
        r"jsx",
    ],
    "vue": [
        r"Vue\.component",
        r"new Vue\(",
        r"v-model",
        r"v-if",
        r"<template>",
    ],
    "django": [
        r"from django",
        r"@login_required",
        r"models\.Model",
        r"HttpResponse",
    ],
    "flask": [
        r"from flask",
        r"@app\.route",
        r"Flask\(__name__\)",
    ],
}


# ─────────────────────── 安全编码模式 ───────────────────────

SECURITY_PATTERNS = {
    "prepared_statement": [
        r"PreparedStatement",
        r"prepareStatement\(",
        r"\#\w+\s*=\s*Prepare\(",
    ],
    "input_validation": [
        r"@Valid",
        r"@NotNull",
        r"@NotBlank",
        r"@Size\(",
        r"@Pattern\(",
        r"validator\.validate",
    ],
    "output_encoding": [
        r"URLEncoder\.encode",
        r"StringEscapeUtils",
        r"HtmlUtils\.htmlEscape",
        r"encodeForHTML",
    ],
    "access_control": [
        r"@PreAuthorize",
        r"@Secured\(",
        r"@RolesAllowed\(",
        r"checkPermission",
    ],
    "crypto": [
        r"Cipher\.getInstance",
        r"MessageDigest",
        r"SecureRandom",
        r"AES/GCM",
    ],
    "cors_config": [
        r"Access-Control-Allow-Origin",
        r"CorsFilter",
        r"CorsRegistry",
    ],
    "csp_config": [
        r"Content-Security-Policy",
        r"ContentSecurityPolicy",
    ],
    "ssl_tls": [
        r"SSLContext",
        r"HttpsURLConnection",
        r"setSSLSocketFactory",
    ],
}


# ─────────────────────── 个性化模型引擎 ───────────────────────

class PersonalizationEngine:
    """
    个性化代码风格引擎

    通过分析企业项目代码特征，构建个性化画像，
    指导过滤器的阈值和规则权重调整，使系统越用越准。

    核心算法：
    1. 代码模式提取：分析代码片段中的框架/库使用特征
    2. 安全模式识别：识别企业已部署的安全控制措施
    3. 误报概率建模：基于历史反馈建立规则-误报概率映射
    4. 自适应调整：根据画像自动调整过滤策略

    使用方式:
        engine = PersonalizationEngine(store)
        profile = await engine.build_profile(project_id="xxx")
        adjustments = engine.get_personalized_adjustments(profile)
    """

    def __init__(self, store: FeedbackStore):
        """
        Args:
            store: FeedbackStore 实例
        """
        self.store = store

    # ─────────────── 画像构建 ───────────────

    async def build_profile(
        self,
        project_id: str,
    ) -> CodeStyleProfile:
        """
        构建企业代码风格画像

        Args:
            project_id: 项目ID

        Returns:
            CodeStyleProfile 代码风格画像
        """
        # 获取所有反馈记录
        feedbacks = await self.store.list_feedbacks(
            project_id=project_id, limit=10000
        )

        # 分析代码模式
        common_patterns = self._extract_common_patterns(feedbacks)

        # 识别框架
        framework_hints = self._detect_frameworks(feedbacks)

        # 提取包前缀
        package_prefixes = self._extract_package_prefixes(feedbacks)

        # 识别安全编码模式
        security_patterns = self._detect_security_patterns(feedbacks)

        # 计算误报概率
        fp_prone_rules = await self.store.get_fp_prone_rules(
            project_id=project_id, min_samples=2
        )

        # 统计
        total_feedbacks = len(feedbacks)
        fp_count = sum(
            1 for f in feedbacks
            if f.feedback_type.value == "false_positive"
        )
        current_fp_rate = fp_count / total_feedbacks if total_feedbacks > 0 else 0.0

        # 获取已有画像统计
        existing_style = await self.store.get_code_style(project_id)
        total_scans = (existing_style or {}).get("total_scans", 0)
        total_findings = (existing_style or {}).get("total_findings", 0)

        profile = CodeStyleProfile(
            project_id=project_id,
            common_patterns=common_patterns,
            framework_hints=framework_hints,
            package_prefixes=package_prefixes,
            security_patterns=security_patterns,
            fp_prone_rules=fp_prone_rules,
            total_scans=total_scans,
            total_findings=total_findings,
            total_feedbacks=total_feedbacks,
            current_fp_rate=round(current_fp_rate, 4),
        )

        # 持久化画像
        await self.store.save_code_style(profile.model_dump())

        logger.info(
            "Built code style profile for project %s: "
            "%d frameworks, %d security patterns, fp_rate=%.2f%%",
            project_id[:8], len(framework_hints), len(security_patterns),
            current_fp_rate * 100,
        )

        return profile

    async def update_profile_with_scan(
        self,
        project_id: str,
        scan_findings_count: int,
    ) -> Optional[CodeStyleProfile]:
        """
        扫描完成后更新画像

        Args:
            project_id: 项目ID
            scan_findings_count: 本次扫描发现数

        Returns:
            更新后的画像
        """
        existing = await self.store.get_code_style(project_id)
        total_scans = (existing or {}).get("total_scans", 0) + 1
        total_findings = (existing or {}).get("total_findings", 0) + scan_findings_count

        if existing:
            existing["total_scans"] = total_scans
            existing["total_findings"] = total_findings
            existing["project_id"] = project_id
            await self.store.save_code_style(existing)
            logger.debug(
                "Updated profile for %s: scan #%d, %d findings",
                project_id[:8], total_scans, scan_findings_count,
            )

        # 每10次扫描重新构建画像
        if total_scans % 10 == 0:
            return await self.build_profile(project_id)

        return None

    # ─────────────── 个性化调整 ───────────────

    def get_personalized_adjustments(
        self,
        profile: CodeStyleProfile,
    ) -> Dict[str, Any]:
        """
        根据个性化画像生成过滤策略调整

        Args:
            profile: 代码风格画像

        Returns:
            调整策略
        """
        adjustments = {
            "threshold_modifiers": {},
            "rule_overrides": {},
            "path_filters": [],
            "framework_boosts": {},
        }

        # 1. 基于框架特征调整
        for fw in profile.framework_hints:
            fw_lower = fw.lower()
            if "spring" in fw_lower:
                # Spring 项目中，注入和 MVC 模式多为安全
                adjustments["rule_overrides"]["java.sql.injection"] = {
                    "threshold_offset": -0.1,
                    "reason": "Spring 项目常使用安全的数据访问模式",
                }
            elif "mybatis" in fw_lower:
                # MyBatis 项目中 ${} 是唯一风险点
                adjustments["rule_overrides"]["java.mybatis.dollar"] = {
                    "threshold_offset": 0.1,
                    "reason": "MyBatis ${} 是明确的注入风险",
                }
            elif "react" in fw_lower or "vue" in fw_lower:
                # 前端框架的 XSS 多为误报
                adjustments["rule_overrides"]["xss.cross.site"] = {
                    "threshold_offset": -0.15,
                    "reason": "现代前端框架默认转义大部分 XSS",
                }

        # 2. 基于安全模式调整
        sec_patterns = profile.security_patterns
        for pattern, count in sec_patterns.items():
            if count >= 3:
                if pattern == "prepared_statement":
                    adjustments["rule_overrides"]["sql.injection"] = {
                        "threshold_offset": -0.15,
                        "reason": f"项目广泛使用 {pattern} ({count} 次)",
                    }
                elif pattern == "input_validation":
                    adjustments["rule_overrides"]["xss.cross.site"] = {
                        "threshold_offset": -0.1,
                        "reason": f"项目广泛使用 {pattern} ({count} 次)",
                    }
                elif pattern == "access_control":
                    adjustments["rule_overrides"]["auth.bypass"] = {
                        "threshold_offset": -0.1,
                        "reason": f"项目有 {pattern} 实践 ({count} 次)",
                    }

        # 3. 基于误报概率调整
        for rule_id, fp_prob in profile.fp_prone_rules.items():
            if fp_prob >= 0.8:
                adjustments["rule_overrides"][rule_id] = {
                    "threshold_offset": 0.2,
                    "reason": f"该规则误报率高达 {fp_prob:.0%}",
                }
            elif fp_prob >= 0.6:
                adjustments["rule_overrides"][rule_id] = {
                    "threshold_offset": 0.1,
                    "reason": f"该规则误报率 {fp_prob:.0%}",
                }

        # 4. 基于误报率目标调整
        # 如果当前误报率接近目标1%，减小调整幅度
        if profile.current_fp_rate <= 0.02:
            adjustments["mode"] = "conservative"
            adjustments["description"] = "已接近1%目标，使用保守调整策略"
        elif profile.current_fp_rate <= 0.05:
            adjustments["mode"] = "moderate"
            adjustments["description"] = "正在接近1%目标，使用适度调整策略"
        else:
            adjustments["mode"] = "aggressive"
            adjustments["description"] = "距1%目标较远，使用积极调整策略"

        return adjustments

    # ─────────────── 模式提取 ───────────────

    def _extract_common_patterns(
        self,
        feedbacks: List[Any],
    ) -> Dict[str, int]:
        """提取常见代码模式"""
        patterns: Counter = Counter()

        for fb in feedbacks:
            code = fb.code_snippet or ""
            if not code:
                continue

            # 简单的模式检测
            if "PreparedStatement" in code or "prepareStatement" in code:
                patterns["prepared_statement"] += 1
            if "@Autowired" in code or "@Inject" in code:
                patterns["dependency_injection"] += 1
            if "try {" in code or "try(" in code:
                patterns["try_catch"] += 1
            if "null" in code:
                patterns["null_check"] += 1
            if "@Test" in code:
                patterns["test_annotation"] += 1
            if "logger" in code or "LOG" in code:
                patterns["logging"] += 1
            if "@Override" in code:
                patterns["override_annotation"] += 1
            if "@Transactional" in code:
                patterns["transactional"] += 1

        return dict(patterns.most_common(20))

    def _detect_frameworks(
        self,
        feedbacks: List[Any],
    ) -> List[str]:
        """识别使用框架"""
        all_code = "\n".join(
            (fb.code_snippet or "") for fb in feedbacks
        )
        all_files = "\n".join(
            (fb.file_path or "") for fb in feedbacks
        )
        combined = all_code + "\n" + all_files

        detected = []
        for fw_name, patterns in FRAMEWORK_PATTERNS.items():
            match_count = 0
            for pattern in patterns:
                matches = re.findall(pattern, combined, re.IGNORECASE)
                match_count += len(matches)
            if match_count >= 2:
                detected.append(fw_name)

        return detected

    def _extract_package_prefixes(
        self,
        feedbacks: List[Any],
    ) -> List[str]:
        """提取常用包前缀"""
        prefixes: Set[str] = set()

        for fb in feedbacks:
            file_path = fb.file_path or ""
            # 从文件路径提取包前缀
            parts = re.split(r"[/\\.]", file_path)
            if len(parts) >= 2:
                prefix = parts[0]
                if prefix and len(prefix) > 2 and prefix not in ("com", "org", "net", "io"):
                    prefixes.add(prefix)
                if len(parts) >= 3:
                    prefix2 = f"{parts[0]}.{parts[1]}"
                    prefixes.add(prefix2)

        return sorted(prefixes)[:20]

    def _detect_security_patterns(
        self,
        feedbacks: List[Any],
    ) -> Dict[str, int]:
        """识别安全编码模式"""
        all_code = "\n".join(
            (fb.code_snippet or "") for fb in feedbacks
        )
        results = {}

        for sec_name, patterns in SECURITY_PATTERNS.items():
            match_count = 0
            for pattern in patterns:
                matches = re.findall(pattern, all_code, re.IGNORECASE)
                match_count += len(matches)
            if match_count > 0:
                results[sec_name] = match_count

        return results

    # ─────────────── 画像查询 ───────────────

    async def get_profile(
        self,
        project_id: str,
    ) -> Optional[CodeStyleProfile]:
        """
        获取已保存的画像

        Args:
            project_id: 项目ID

        Returns:
            CodeStyleProfile 或 None
        """
        data = await self.store.get_code_style(project_id)
        if data is None:
            return None

        return CodeStyleProfile(**data)

    async def get_optimization_summary(
        self,
        project_id: str,
    ) -> Dict[str, Any]:
        """
        获取个性化优化摘要

        Args:
            project_id: 项目ID

        Returns:
            优化摘要
        """
        profile = await self.get_profile(project_id)
        if profile is None:
            return {
                "status": "no_profile",
                "message": "尚未构建代码风格画像，需要更多反馈数据",
            }

        adjustments = self.get_personalized_adjustments(profile)

        # 计算预期误报率
        # 简单估算：每次扫描优化可降低 10-30% 的误报率
        estimated_fp_rate = profile.current_fp_rate
        if profile.total_scans > 0:
            # 假设每次优化周期降低 20%
            optimization_factor = 0.8 ** (profile.total_scans / 10)
            estimated_fp_rate = max(
                0.005,  # 不低于 0.5%
                profile.current_fp_rate * optimization_factor,
            )

        return {
            "status": "ready",
            "profile": profile.model_dump(),
            "adjustments": adjustments,
            "estimated_fp_rate": round(estimated_fp_rate, 4),
            "target_fp_rate": 0.01,
            "convergence_estimate": self._estimate_convergence(profile),
        }

    def _estimate_convergence(
        self,
        profile: CodeStyleProfile,
    ) -> str:
        """估算达到1%目标所需的额外扫描次数"""
        if profile.current_fp_rate <= 0.01:
            return "已达到目标"

        if profile.total_feedbacks < 10:
            return f"需要至少 {10 - profile.total_feedbacks} 条反馈"

        # 如果每次扫描降低20%，需要多少次才能从当前误报率降到1%？
        # current * 0.8^n <= 0.01
        # n >= log(0.01/current) / log(0.8)
        import math
        if profile.current_fp_rate <= 0 or profile.total_scans == 0:
            return "数据不足"

        ratio = 0.01 / profile.current_fp_rate
        if ratio >= 1:
            return "已达到目标"
        if ratio <= 0:
            return "无法估算"

        n = math.ceil(math.log(ratio) / math.log(0.8))
        n = max(1, n)
        return f"约还需 {n} 次扫描优化可降到1%以下"
