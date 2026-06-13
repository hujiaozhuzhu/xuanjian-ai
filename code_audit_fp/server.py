"""
MCP服务器实现 (适配 MCP SDK >=1.0)

使用 FastMCP 装饰器模式注册工具
三层误报过滤架构：
1. L1: 规则过滤 - 基于白名单/黑名单的快速过滤
2. L2: 上下文分析 - 死代码检测、安全守卫识别
3. L3: ML置信度评分 - 机器学习模型评估
"""

import asyncio
import json
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .models import (
    ScanResult, FilterResult, FilterResponse, FilterStatistics,
    ContextAnalysisRequest, ContextAnalysisResult,
    TrainingRequest, TrainingResult, TrainingDataItem
)
from .filters import RuleFilter, ContextFilter, MLFilter


class CodeAuditFPServer:
    """代码审计误报过滤MCP服务器"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        初始化服务器
        
        Args:
            config_path: 配置文件路径
        """
        self.config = self._load_config(config_path)
        self.logger = logging.getLogger("code_audit_fp")
        
        # 初始化过滤器
        self.rule_filter = RuleFilter(self.config.get("rule_filter", {}))
        self.context_filter = ContextFilter(self.config.get("context_filter", {}))
        self.ml_filter = MLFilter(self.config.get("ml_filter", {}))
        
        # 创建 FastMCP 服务器
        self.mcp = FastMCP("code-audit-fp")
        self._register_tools()
    
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        加载配置文件
        
        Args:
            config_path: 配置文件路径
            
        Returns:
            Dict[str, Any]: 配置字典
        """
        default_config = {
            "rule_filter": {
                "enabled": True,
                "global_whitelist": [],
                "global_blacklist": []
            },
            "context_filter": {
                "enabled": True,
                "security_guard_keywords": [
                    "sanitize", "escape", "validate", "verify", "check",
                    "clean", "purify", "encode", "decode", "hash",
                    "encrypt", "decrypt", "sign", "verify", "authorize",
                    "authenticate", "permission", "role", "access"
                ],
                "false_positive_threshold": 0.5
            },
            "ml_filter": {
                "enabled": True,
                "model_path": "models/false_positive_model.pkl",
                "onnx_model_path": "models/false_positive_model.onnx",
                "confidence_threshold": 0.7
            }
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    # 合并配置
                    self._merge_config(default_config, user_config)
            except Exception as e:
                print(f"加载配置文件失败: {e}")
        
        return default_config
    
    def _merge_config(self, base: Dict, override: Dict):
        """
        合并配置
        
        Args:
            base: 基础配置
            override: 覆盖配置
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def _register_tools(self):
        """注册MCP工具 (使用 FastMCP 装饰器)"""
        server = self
        
        @self.mcp.tool()
        async def filter_false_positives(
            scan_results: List[Dict[str, Any]],
            source_code_dir: str = ".",
            filter_level: str = "all",
            confidence_threshold: float = 0.7
        ) -> str:
            """
            过滤静态分析工具的扫描结果，识别并标记误报。
            
            Args:
                scan_results: 扫描结果列表，每项包含 tool, rule_id, file, line, code, severity, message
                source_code_dir: 源代码目录
                filter_level: 过滤层级 ("L1", "L2", "L3", "all")
                confidence_threshold: 置信度阈值 (0-1)
                
            Returns:
                JSON格式的过滤结果和统计信息
            """
            try:
                # 解析扫描结果
                parsed_results = []
                for result in scan_results:
                    try:
                        scan_result = ScanResult(**result)
                        parsed_results.append(scan_result)
                    except Exception as e:
                        server.logger.warning(f"解析扫描结果失败: {e}")
                
                # 应用过滤器
                filtered_results = []
                for scan_result in parsed_results:
                    result = await server._apply_filters(
                        scan_result, filter_level, confidence_threshold
                    )
                    filtered_results.append(result)
                
                # 计算统计信息
                statistics = server._calculate_statistics(filtered_results)
                
                # 构建响应
                response = FilterResponse(
                    filtered_results=filtered_results,
                    statistics=statistics
                )
                
                return json.dumps(response.model_dump(), ensure_ascii=False, indent=2)
                
            except Exception as e:
                server.logger.error(f"过滤误报失败: {e}")
                return json.dumps({"error": str(e)}, ensure_ascii=False)
        
        @self.mcp.tool()
        async def analyze_code_context(
            file_path: str,
            line_number: int,
            context_lines: int = 10,
        ) -> str:
            """
            分析代码上下文，识别可能导致误报的因素。
            
            Args:
                file_path: 文件路径
                line_number: 行号
                context_lines: 上下文行数
                
            Returns:
                JSON格式的上下文分析结果
            """
            try:
                # 创建模拟的扫描结果用于分析
                mock_scan_result = ScanResult(
                    tool="semgrep",
                    rule_id="manual_analysis",
                    file=file_path,
                    line=line_number,
                    code="",  # 将由上下文过滤器读取
                    severity="WARNING",
                    message="手动上下文分析"
                )
                
                # 使用上下文过滤器分析
                context_result = await server.context_filter._analyze_context(mock_scan_result)
                
                return json.dumps(context_result.model_dump(), ensure_ascii=False, indent=2)
                
            except Exception as e:
                server.logger.error(f"上下文分析失败: {e}")
                return json.dumps({"error": str(e)}, ensure_ascii=False)
        
        @self.mcp.tool()
        async def train_false_positive_model(
            training_data: List[Dict[str, Any]],
            model_type: str = "random_forest",
            validation_split: float = 0.2
        ) -> str:
            """
            使用历史数据训练误报识别模型。
            
            Args:
                training_data: 训练数据列表，每项包含 features(字典) 和 is_false_positive(布尔)
                model_type: 模型类型 ("random_forest", "gradient_boosting", "svm")
                validation_split: 验证集比例
                
            Returns:
                JSON格式的训练结果
            """
            try:
                # 解析训练数据
                parsed_data = []
                for item in training_data:
                    try:
                        data_item = TrainingDataItem(**item)
                        parsed_data.append(data_item.model_dump())
                    except Exception as e:
                        server.logger.warning(f"解析训练数据失败: {e}")
                
                # 训练模型
                result = await server.ml_filter.train_model(
                    parsed_data, model_type, validation_split
                )
                
                return json.dumps(result, ensure_ascii=False, indent=2)
                
            except Exception as e:
                server.logger.error(f"训练模型失败: {e}")
                return json.dumps({"error": str(e)}, ensure_ascii=False)
        
        @self.mcp.tool()
        async def get_filter_status() -> str:
            """
            获取过滤器状态和配置信息。
            
            Returns:
                JSON格式的过滤器状态
            """
            status = {
                "rule_filter": {
                    "enabled": server.rule_filter.enabled,
                    "config": server.rule_filter.config
                },
                "context_filter": {
                    "enabled": server.context_filter.enabled,
                    "config": server.context_filter.config
                },
                "ml_filter": {
                    "enabled": server.ml_filter.enabled,
                    "model_loaded": server.ml_filter.model is not None or server.ml_filter.onnx_session is not None,
                    "config": server.ml_filter.config
                }
            }
            
            return json.dumps(status, ensure_ascii=False, indent=2)
    
    async def _apply_filters(
        self,
        scan_result: ScanResult,
        filter_level: str,
        confidence_threshold: float
    ) -> FilterResult:
        """
        应用过滤器
        
        Args:
            scan_result: 扫描结果
            filter_level: 过滤层级
            confidence_threshold: 置信度阈值
            
        Returns:
            FilterResult: 过滤结果
        """
        current_result = None
        
        # L1: 规则过滤
        if filter_level in ["L1", "all"]:
            current_result = await self.rule_filter.filter(scan_result)
            if current_result.is_false_positive and current_result.confidence >= confidence_threshold:
                return current_result
        
        # L2: 上下文过滤
        if filter_level in ["L2", "all"]:
            if current_result is None:
                current_result = await self.context_filter.filter(scan_result)
            else:
                # 如果L1没有过滤掉，继续L2
                context_result = await self.context_filter.filter(scan_result)
                if context_result.is_false_positive and context_result.confidence >= confidence_threshold:
                    return context_result
        
        # L3: ML过滤
        if filter_level in ["L3", "all"]:
            if current_result is None:
                current_result = await self.ml_filter.filter(scan_result)
            else:
                # 如果L1和L2都没有过滤掉，继续L3
                ml_result = await self.ml_filter.filter(scan_result)
                if ml_result.is_false_positive and ml_result.confidence >= confidence_threshold:
                    return ml_result
        
        # 如果没有过滤掉，返回最后的结果
        if current_result is None:
            # 创建默认结果
            current_result = FilterResult(
                original=scan_result,
                is_false_positive=False,
                confidence=0.5,
                filter_reasons=[],
                risk_score=5.0,
                recommendation="未应用任何过滤器"
            )
        
        return current_result
    
    def _calculate_statistics(self, results: List[FilterResult]) -> FilterStatistics:
        """
        计算统计信息
        
        Args:
            results: 过滤结果列表
            
        Returns:
            FilterStatistics: 统计信息
        """
        total = len(results)
        false_positives = sum(1 for r in results if r.is_false_positive)
        true_positives = total - false_positives
        
        reduction_rate = f"{(false_positives / total * 100):.1f}%" if total > 0 else "0%"
        
        # 计算各层级过滤统计
        filter_level_stats = {"L1": 0, "L2": 0, "L3": 0}
        for result in results:
            for reason in result.filter_reasons:
                if reason.filter_level in filter_level_stats:
                    filter_level_stats[reason.filter_level] += 1
        
        return FilterStatistics(
            total=total,
            false_positives=false_positives,
            true_positives=true_positives,
            reduction_rate=reduction_rate,
            processing_time_ms=0,  # TODO: 实际计时
            filter_level_stats=filter_level_stats
        )
    
    async def run(self, transport: str = "stdio", port: int = 8000):
        """
        运行服务器
        
        Args:
            transport: 传输方式 ("stdio" 或 "sse")
            port: 端口号 (仅SSE模式)
        """
        if transport == "stdio":
            await self.mcp.run_stdio_async()
        elif transport == "sse":
            await self.mcp.run_sse_async(host="0.0.0.0", port=port)
        else:
            raise ValueError(f"不支持的传输方式: {transport}")


def create_server(config_path: Optional[str] = None) -> CodeAuditFPServer:
    """
    创建服务器实例
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        CodeAuditFPServer: 服务器实例
    """
    return CodeAuditFPServer(config_path)


async def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description="代码审计误报过滤MCP服务器")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio",
                       help="传输方式")
    parser.add_argument("--port", type=int, default=8000,
                       help="端口号 (仅SSE模式)")
    parser.add_argument("--config", type=str, default=None,
                       help="配置文件路径")
    
    args = parser.parse_args()
    
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # 创建并运行服务器
    server = create_server(args.config)
    await server.run(args.transport, args.port)


if __name__ == "__main__":
    asyncio.run(main())
