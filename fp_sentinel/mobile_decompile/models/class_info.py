"""类/方法/字段信息数据模型。

玄鉴 v4.0 能力② 反编译引擎 —— 反编译产物的结构化表示。
对应规划文档 2.2.2 节 models/class_info.py 与 models/method_info.py。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class FieldInfo:
    """类字段信息。"""

    name: str
    type_desc: str = ""
    access_flags: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "type_desc": self.type_desc,
            "access_flags": self.access_flags,
        }


@dataclass
class MethodInfo:
    """方法信息（参数/返回/访问标志）。

    对应规划文档 models/method_info.py 的职责。
    """

    name: str
    descriptor: str = ""
    access_flags: str = ""
    class_name: str = ""

    @property
    def full_signature(self) -> str:
        """完整方法签名，如 ``Lcom/pkg/Cls;->foo(I)V``。"""
        if "->" in self.descriptor:
            return self.descriptor
        return f"{self.class_name}->{self.name}{self.descriptor}"

    @property
    def simple_signature(self) -> str:
        """``Cls.foo(I)V`` 形式的短签名。"""
        cls = self.class_name.lstrip("L").rstrip(";").rsplit("/", 1)[-1]
        return f"{cls}.{self.name}{self.descriptor}"

    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "descriptor": self.descriptor,
            "access_flags": self.access_flags,
            "class_name": self.class_name,
            "full_signature": self.full_signature,
        }


@dataclass
class ClassInfo:
    """类信息（包名/方法/属性）。"""

    name: str  # 如 Lcom/pkg/Cls;
    super_name: str = ""
    interfaces: List[str] = field(default_factory=list)
    methods: List[MethodInfo] = field(default_factory=list)
    fields: List[FieldInfo] = field(default_factory=list)

    @property
    def java_name(self) -> str:
        """``Lcom/pkg/Cls;`` -> ``com.pkg.Cls``。"""
        return self.name.lstrip("L").rstrip(";").replace("/", ".")

    @property
    def package(self) -> str:
        """Java 包名（不含类名）。"""
        java = self.java_name
        return java.rsplit(".", 1)[0] if "." in java else ""

    def is_internal(self, app_package: Optional[str] = None) -> bool:
        """判断是否属于业务包（而非第三方 SDK）。"""
        if not app_package:
            return False
        return self.package == app_package or self.package.startswith(app_package + ".")

    def find_methods(self, keyword: str, case_sensitive: bool = False) -> List[MethodInfo]:
        """按关键字过滤方法名。"""
        kw = keyword if case_sensitive else keyword.lower()
        out: List[MethodInfo] = []
        for m in self.methods:
            name = m.name if case_sensitive else m.name.lower()
            if kw in name:
                out.append(m)
        return out

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "java_name": self.java_name,
            "super_name": self.super_name,
            "interfaces": list(self.interfaces),
            "methods": [m.to_dict() for m in self.methods],
            "fields": [f.to_dict() for f in self.fields],
        }


@dataclass
class ClassNode:
    """类层次树节点。"""

    name: str
    parent: Optional[str] = None
    children: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {"name": self.name, "parent": self.parent, "children": list(self.children)}


@dataclass
class ClassHierarchy:
    """类层次结构（继承树）。"""

    nodes: Dict[str, ClassNode] = field(default_factory=dict)

    def add_class(self, name: str, parent: Optional[str] = None) -> None:
        node = self.nodes.setdefault(name, ClassNode(name=name))
        if parent:
            node.parent = parent
            pnode = self.nodes.setdefault(parent, ClassNode(name=parent))
            if name not in pnode.children:
                pnode.children.append(name)

    def get_children(self, name: str) -> List[str]:
        node = self.nodes.get(name)
        return list(node.children) if node else []

    def get_ancestors(self, name: str) -> List[str]:
        """自底向上返回祖先链（不含自身）。"""
        chain: List[str] = []
        cur = self.nodes.get(name)
        seen: set = set()
        while cur and cur.parent and cur.parent not in seen:
            chain.append(cur.parent)
            seen.add(cur.parent)
            cur = self.nodes.get(cur.parent)
        return chain

    def get_descendants(self, name: str) -> List[str]:
        """广度优先返回全部子孙类（不含自身，带环检测）。"""
        out: List[str] = []
        visited: set = {name}
        queue = list(self.get_children(name))
        while queue:
            cur = queue.pop(0)
            if cur in visited:
                continue
            visited.add(cur)
            out.append(cur)
            queue.extend(self.get_children(cur))
        return out

    def __len__(self) -> int:
        return len(self.nodes)

    def to_dict(self) -> Dict[str, object]:
        return {name: node.to_dict() for name, node in self.nodes.items()}
