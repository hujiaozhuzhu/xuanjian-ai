# -*- coding: utf-8 -*-
"""DexBaksmali —— 零外部依赖的 DEX 兜底解析器（纯 Python struct 解析）。

当 jadx + androguard 均失败时，提供：
- 可读的类 / 方法列表（按 baksmali 风格 smali 格式输出）；
- 字符串搜索（URL / key / token 等审计关键信息）；
- 结构化查询（按类名 / 方法名定位）。

文件格式参考：Android 官方 dex-format
https://source.android.com/docs/core/runtime/dex-format

仅依赖 Python 标准库（struct），零网络、零外部安装。
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────
# 数据结构
# ─────────────────────────────────────────────────────────────

@dataclass
class BaksmaliMethod:
    """单条方法信息（DEX 解析产物）。"""
    name: str = ""
    class_name: str = ""           # 原始内部名 Lcom/pkg/Cls;
    descriptor: str = ""           # (I)Ljava/lang/String;
    shorty: str = ""               # 方法短签名
    access_flags: int = 0
    code_offset: int = 0           # code_item 在 DEX 中的偏移
    code_item_size: int = 0        # code_item 大小（指令字节数）
    registers_size: int = 0
    ins_size: int = 0
    outs_size: int = 0
    tries_size: int = 0
    debug_info_off: int = 0
    insns: bytes = b""             # 原始指令字节
    tries: list = field(default_factory=list)
    debug_info: str = ""


@dataclass
class BaksmaliClass:
    """单条类信息（DEX 解析产物）。"""
    class_name: str = ""           # Lcom/pkg/Cls;
    super_class: str = ""
    source_file: str = ""
    access_flags: int = 0
    interfaces: List[str] = field(default_factory=list)
    methods: List[BaksmaliMethod] = field(default_factory=list)
    static_fields: List[Tuple[str, str, int]] = field(default_factory=list)  # (name, type, access_flags)
    instance_fields: List[Tuple[str, str, int]] = field(default_factory=list)
    annotations_off: int = 0


# ─────────────────────────────────────────────────────────────
# DEX 解析器
# ─────────────────────────────────────────────────────────────

class DexBaksmali:
    """纯 Python DEX 格式解析器（零外部依赖）。

    用法::

        with open("classes.dex", "rb") as f:
            dex = DexBaksmali(f.read())
        dex.parse_dex(dex_bytes)
        cls = dex.get_class("Lcom/example/MyClass;")
        method = dex.find_method("Lcom/example/MyClass;", "onCreate")
        strings = dex.find_string("https://")
    """

    # DEX 头部字段偏移（见 dex-format 规范）
    _HDR_MAGIC = (0, 8)         # "dex\\n035\\0"
    _HDR_CHECKSUM = (8, 4)      # uint32
    _HDR_SIGNATURE = (12, 20)   # 20 bytes
    _HDR_FILE_SIZE = (32, 4)    # uint32
    _HDR_HEADER_SIZE = (36, 4)  # uint32 (usually 0x70)
    _HDR_ENDIAN_TAG = (40, 4)   # uint32 (0x12345678)
    _HDR_STRING_IDS_SIZE = (56, 4)
    _HDR_STRING_IDS_OFF = (60, 4)
    _HDR_TYPE_IDS_SIZE = (64, 4)
    _HDR_TYPE_IDS_OFF = (68, 4)
    _HDR_PROTO_IDS_SIZE = (72, 4)
    _HDR_PROTO_IDS_OFF = (76, 4)
    _HDR_FIELD_IDS_SIZE = (80, 4)
    _HDR_FIELD_IDS_OFF = (84, 4)
    _HDR_METHOD_IDS_SIZE = (88, 4)
    _HDR_METHOD_IDS_OFF = (92, 4)
    _HDR_CLASS_DEFS_SIZE = (96, 4)
    _HDR_CLASS_DEFS_OFF = (100, 4)
    _HDR_DATA_SIZE = (104, 4)
    _HDR_DATA_OFF = (108, 4)

    def __init__(self) -> None:
        self._data: bytes = b""
        self._file_size: int = 0
        self._big_endian: bool = False
        # 解析结果
        self._strings: List[str] = []
        self._string_offsets: List[int] = []
        self._types: List[int] = []          # type -> string_ids index
        self._protos: List[dict] = []        # {shorty_idx, return_type_idx, params_off/args}
        self._fields: List[dict] = []        # {class_idx, type_idx, name_idx}
        self._methods: List[dict] = []       # {class_idx, proto_idx, name_idx}
        self._classes: List[BaksmaliClass] = []
        self._parsed = False

    # ─────────────────────── 主入口 ───────────────────────

    def parse_dex(self, dex_bytes: bytes) -> None:
        """按 DEX 格式解析字节数据。

        解析顺序: header -> string_ids -> type_ids -> proto_ids ->
        field_ids -> method_ids -> class_defs -> class_data -> code_item
        """
        if len(dex_bytes) < 112:
            raise ValueError(f"DEX 文件过短 ({len(dex_bytes)} bytes)，不是有效 DEX")

        self._data = dex_bytes
        self._file_size = self._read_uint32(32)
        endian_tag = self._read_uint32(40)
        self._big_endian = (endian_tag != 0x12345678)

        # 1) 解析字符串表
        self._parse_strings()
        # 2) 解析 type_ids
        self._parse_types()
        # 3) 解析 proto_ids
        self._parse_protos()
        # 4) 解析 field_ids
        self._parse_fields()
        # 5) 解析 method_ids
        self._parse_method_ids()
        # 6) 解析 class_defs → class_data → code_item
        self._parse_class_defs()

        self._parsed = True

    # ─────────────────────── Header 工具 ───────────────────────

    def _endian_prefix(self) -> str:
        return ">" if self._big_endian else "<"

    def _read_uint32(self, offset: int) -> int:
        return struct.unpack(self._endian_prefix() + "I", self._data[offset:offset + 4])[0]

    def _read_uint16(self, offset: int) -> int:
        return struct.unpack(self._endian_prefix() + "H", self._data[offset:offset + 2])[0]

    def _read_int32(self, offset: int) -> int:
        return struct.unpack(self._endian_prefix() + "i", self._data[offset:offset + 4])[0]

    # ─────────────────────── 字符串表 ───────────────────────

    def _parse_strings(self) -> None:
        """解析 string_ids → string_data（MUTF-8 编码）。"""
        str_ids_size = self._read_uint32(56)
        str_ids_off = self._read_uint32(60)
        # 读取 string 偏移数组
        offsets: List[int] = []
        fmt = self._endian_prefix() + "I"
        for i in range(str_ids_size):
            off = str_ids_off + i * 4
            if off + 4 > len(self._data):
                break
            offsets.append(struct.unpack(fmt, self._data[off:off + 4])[0])
        # 读取每个字符串内容
        strings: List[str] = []
        for off in offsets:
            if off >= len(self._data):
                strings.append("")
                continue
            strings.append(self._read_mutf8(off))
        self._strings = strings
        self._string_offsets = offsets

    def _read_mutf8(self, offset: int) -> str:
        """读取 DEX MUTF-8 编码字符串（简化版，支持常见 UTF-8 + null 终止）。"""
        if offset >= len(self._data):
            return ""
        # 跳过 uleb128 长度编码
        _, bytes_read = self._read_uleb128_from_bytes(self._data[offset:])
        start = offset + bytes_read
        end = start
        while end < len(self._data) and self._data[end] != 0:
            end += 1
        raw = self._data[start:end]
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return raw.decode("latin-1", errors="replace")

    @staticmethod
    def _read_uleb128_from_bytes(data: bytes) -> Tuple[int, int]:
        """从 bytes 对象读取 ULEB128 编码的整数。

        :return: (值, 读取字节数)
        """
        result = 0
        shift = 0
        for i, byte in enumerate(data):
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                return result, i + 1
            shift += 7
            if shift >= 64:
                break
        return result, 1

    def _read_uleb128_from_data(self, offset: int) -> Tuple[int, int]:
        """从 self._data 的偏移处读取 ULEB128，返回 (值, 读取字节数)。"""
        data = self._data[offset:]
        result = 0
        shift = 0
        for i, byte in enumerate(data):
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                return result, i + 1
            shift += 7
            if shift >= 64:
                break
        return result, 1

    def _read_sleb128_from_data(self, offset: int) -> Tuple[int, int]:
        """从 self._data 的偏移处读取 SLEB128，返回 (值, 读取字节数)。"""
        data = self._data[offset:]
        result = 0
        shift = 0
        for i, byte in enumerate(data):
            result |= (byte & 0x7F) << shift
            shift += 7
            if (byte & 0x80) == 0:
                if shift < 64 and (byte & 0x40):
                    result |= -(1 << shift)
                return result, i + 1
        return result, 1

    # ─────────────────────── type_ids ───────────────────────

    def _parse_types(self) -> None:
        """解析 type_ids 数组（每个 entry 是 string_ids index）。"""
        type_size = self._read_uint32(64)
        type_off = self._read_uint32(68)
        fmt = self._endian_prefix() + "I"
        types: List[int] = []
        for i in range(type_size):
            off = type_off + i * 4
            if off + 4 > len(self._data):
                break
            types.append(struct.unpack(fmt, self._data[off:off + 4])[0])
        self._types = types

    def _type_name(self, type_idx: int) -> str:
        """将 type_idx 转为完整内部类名 Lcom/pkg/Cls;。"""
        if 0 <= type_idx < len(self._types):
            str_idx = self._types[type_idx]
            if 0 <= str_idx < len(self._strings):
                return self._strings[str_idx]
        return ""

    # ─────────────────────── proto_ids ───────────────────────

    def _parse_protos(self) -> None:
        """解析 proto_ids 数组。"""
        proto_size = self._read_uint32(72)
        proto_off = self._read_uint32(76)
        fmt_u4 = self._endian_prefix() + "I"
        protos: List[dict] = []
        for i in range(proto_size):
            base = proto_off + i * 12  # 每个 proto_id_item 3 * uint32
            if base + 12 > len(self._data):
                break
            shorty_idx = struct.unpack(fmt_u4, self._data[base:base + 4])[0]
            return_type_idx = struct.unpack(fmt_u4, self._data[base + 4:base + 8])[0]
            parameters_off = struct.unpack(fmt_u4, self._data[base + 8:base + 12])[0]
            protos.append({
                "shorty_idx": shorty_idx,
                "return_type_idx": return_type_idx,
                "parameters_off": parameters_off,
            })
            # 解析参数列表
            if parameters_off > 0 and parameters_off + 4 <= len(self._data):
                param_size = struct.unpack(fmt_u4, self._data[parameters_off:parameters_off + 4])[0]
                params: List[int] = []
                limit = min(param_size, 256)
                for j in range(limit):
                    poff = parameters_off + 4 + j * 2
                    if poff + 2 > len(self._data):
                        break
                    params.append(struct.unpack(
                        self._endian_prefix() + "H",
                        self._data[poff:poff + 2])[0])
                protos[-1]["params"] = params
            else:
                protos[-1]["params"] = []
        self._protos = protos

    def _proto_descriptor(self, proto_idx: int) -> str:
        """将 proto_idx 转为 (Ljava/lang/String;)I 形式的描述符。"""
        if 0 <= proto_idx < len(self._protos):
            proto = self._protos[proto_idx]
            params = proto.get("params", [])
            args = "".join(_type_to_descriptor(self._type_name(p)) for p in params)
            ret = _type_to_descriptor(self._type_name(proto["return_type_idx"]))
            return f"({args}){ret}"
        return "()V"

    def _shorty(self, proto_idx: int) -> str:
        if 0 <= proto_idx < len(self._protos):
            shorty_idx = self._protos[proto_idx]["shorty_idx"]
            if 0 <= shorty_idx < len(self._strings):
                return self._strings[shorty_idx]
        return ""

    # ─────────────────────── field_ids ───────────────────────

    def _parse_fields(self) -> None:
        field_size = self._read_uint32(80)
        field_off = self._read_uint32(84)
        fmt_u2 = self._endian_prefix() + "H"
        fmt_u4 = self._endian_prefix() + "I"
        fields: List[dict] = []
        for i in range(field_size):
            base = field_off + i * 8
            if base + 8 > len(self._data):
                break
            class_idx = struct.unpack(fmt_u2, self._data[base:base + 2])[0]
            type_idx = struct.unpack(fmt_u2, self._data[base + 2:base + 4])[0]
            name_idx = struct.unpack(fmt_u4, self._data[base + 4:base + 8])[0]
            fields.append({"class_idx": class_idx, "type_idx": type_idx, "name_idx": name_idx})
        self._fields = fields

    # ─────────────────────── method_ids ───────────────────────

    def _parse_method_ids(self) -> None:
        method_size = self._read_uint32(88)
        method_off = self._read_uint32(92)
        fmt_u2 = self._endian_prefix() + "H"
        fmt_u4 = self._endian_prefix() + "I"
        methods: List[dict] = []
        for i in range(method_size):
            base = method_off + i * 8
            if base + 8 > len(self._data):
                break
            class_idx = struct.unpack(fmt_u2, self._data[base:base + 2])[0]
            proto_idx = struct.unpack(fmt_u2, self._data[base + 2:base + 4])[0]
            name_idx = struct.unpack(fmt_u4, self._data[base + 4:base + 8])[0]
            methods.append({"class_idx": class_idx, "proto_idx": proto_idx, "name_idx": name_idx})
        self._methods = methods

    # ─────────────────────── class_defs ───────────────────────

    def _parse_class_defs(self) -> None:
        """解析 class_defs → class_data_item → encoded_method → code_item。"""
        class_size = self._read_uint32(96)
        class_off = self._read_uint32(100)
        fmt_u4 = self._endian_prefix() + "I"
        classes: List[BaksmaliClass] = []

        for i in range(class_size):
            base = class_off + i * 32  # class_def_item = 8 * uint32
            if base + 32 > len(self._data):
                break
            class_idx = struct.unpack(fmt_u4, self._data[base:base + 4])[0]
            access_flags = struct.unpack(fmt_u4, self._data[base + 4:base + 8])[0]
            superclass_idx = struct.unpack(fmt_u4, self._data[base + 8:base + 12])[0]
            # interfaces_off = struct.unpack(fmt_u4, self._data[base + 12:base + 16])[0]
            source_file_idx = struct.unpack(fmt_u4, self._data[base + 16:base + 20])[0]
            annotations_off = struct.unpack(fmt_u4, self._data[base + 20:base + 24])[0]
            class_data_off = struct.unpack(fmt_u4, self._data[base + 24:base + 28])[0]
            # static_values_off = struct.unpack(fmt_u4, self._data[base + 28:base + 32])[0]

            cls = BaksmaliClass(
                class_name=self._type_name(class_idx),
                super_class=self._type_name(superclass_idx) if superclass_idx != 0xFFFFFFFF else "",
                source_file=self._strings[source_file_idx] if 0 <= source_file_idx < len(self._strings) else "",
                access_flags=access_flags,
                annotations_off=annotations_off,
            )

            # 解析 class_data_item
            if class_data_off > 0 and class_data_off < len(self._data):
                self._parse_class_data(cls, class_data_off)

            classes.append(cls)

        self._classes = classes

    def _parse_class_data(self, cls: BaksmaliClass, data_off: int) -> None:
        """解析 class_data_item，填充 cls.methods / cls.static_fields / cls.instance_fields。"""
        pos = data_off
        static_size, n = self._read_uleb128_from_data(pos)
        pos += n
        instance_size, n = self._read_uleb128_from_data(pos)
        pos += n
        direct_methods_size, n = self._read_uleb128_from_data(pos)
        pos += n
        virtual_methods_size, n = self._read_uleb128_from_data(pos)
        pos += n

        # 解析 static fields
        field_idx = 0
        for _ in range(static_size):
            diff, n = self._read_uleb128_from_data(pos)
            pos += n
            access, n = self._read_uleb128_from_data(pos)
            pos += n
            field_idx += diff
            if 0 <= field_idx < len(self._fields):
                f = self._fields[field_idx]
                name = self._strings[f["name_idx"]] if 0 <= f["name_idx"] < len(self._strings) else ""
                type_name = self._type_name(f["type_idx"])
                cls.static_fields.append((name, type_name, access))

        # 解析 instance fields
        field_idx = 0
        for _ in range(instance_size):
            diff, n = self._read_uleb128_from_data(pos)
            pos += n
            access, n = self._read_uleb128_from_data(pos)
            pos += n
            field_idx += diff
            if 0 <= field_idx < len(self._fields):
                f = self._fields[field_idx]
                name = self._strings[f["name_idx"]] if 0 <= f["name_idx"] < len(self._strings) else ""
                type_name = self._type_name(f["type_idx"])
                cls.instance_fields.append((name, type_name, access))

        # 解析 direct methods
        method_idx = 0
        methods_count = direct_methods_size + virtual_methods_size
        is_direct = True
        for m_idx in range(methods_count):
            if m_idx >= direct_methods_size:
                is_direct = False
            diff, n = self._read_uleb128_from_data(pos)
            pos += n
            access, n = self._read_uleb128_from_data(pos)
            pos += n
            code_off, n = self._read_uleb128_from_data(pos)
            pos += n
            method_idx += diff

            method = BaksmaliMethod(
                access_flags=access,
                code_offset=code_off,
            )
            if 0 <= method_idx < len(self._methods):
                mid = self._methods[method_idx]
                name_idx = mid["name_idx"]
                if 0 <= name_idx < len(self._strings):
                    method.name = self._strings[name_idx]
                method.class_name = self._type_name(mid["class_idx"])
                method.descriptor = self._proto_descriptor(mid["proto_idx"])
                method.shorty = self._shorty(mid["proto_idx"])

            # 解析 code_item
            if code_off > 0 and code_off + 16 <= len(self._data):
                self._parse_code_item(method, code_off)

            cls.methods.append(method)

    def _parse_code_item(self, method: BaksmaliMethod, code_off: int) -> None:
        """解析 code_item 结构：registers/ins/outs/tries/debug/insns。"""
        fmt_u2 = self._endian_prefix() + "H"
        fmt_u4 = self._endian_prefix() + "I"
        try:
            base = code_off
            method.registers_size = struct.unpack(fmt_u2, self._data[base:base + 2])[0]
            method.ins_size = struct.unpack(fmt_u2, self._data[base + 2:base + 4])[0]
            method.outs_size = struct.unpack(fmt_u2, self._data[base + 4:base + 6])[0]
            method.tries_size = struct.unpack(fmt_u2, self._data[base + 6:base + 8])[0]
            method.debug_info_off = struct.unpack(fmt_u4, self._data[base + 8:base + 12])[0]
            insns_size = struct.unpack(fmt_u4, self._data[base + 12:base + 16])[0]
            method.code_item_size = insns_size * 2  # 每条指令 2 bytes

            insns_start = base + 16
            insns_end = insns_start + insns_size * 2
            if insns_end <= len(self._data):
                method.insns = self._data[insns_start:insns_end]

            # 跳过 tries 与 catch_handler（解析用，暂不展开）
        except struct.error:
            pass

    # ─────────────────────── 查询接口 ───────────────────────

    def get_class(self, class_name: str) -> Optional[BaksmaliClass]:
        """从已解析结构中按类名提取（支持内部名和 Java 点号名）。"""
        internal = class_name if class_name.startswith("L") else _java_to_internal(class_name)
        for cls in self._classes:
            if cls.class_name == internal:
                return cls
        # 后缀匹配（容错）
        for cls in self._classes:
            if cls.class_name.rstrip(";").endswith(internal.rstrip(";").replace("L", "")):
                return cls
        return None

    def find_method(self, class_name: str, method_name: str) -> Optional[BaksmaliMethod]:
        """按类名 + 方法名查找方法。"""
        cls = self.get_class(class_name)
        if cls is None:
            return None
        for m in cls.methods:
            if m.name == method_name:
                return m
        return None

    def find_string(self, s: str) -> List[Dict[str, Any]]:
        """搜索 DEX string 池中包含 s 的所有字符串及其索引。"""
        results: List[Dict[str, Any]] = []
        for idx, val in enumerate(self._strings):
            if s and s in val:
                results.append({
                    "index": idx,
                    "value": val,
                    "offset": self._string_offsets[idx] if idx < len(self._string_offsets) else 0,
                })
        return results

    @property
    def all_strings(self) -> List[str]:
        """返回全量字符串表。"""
        return list(self._strings)

    @property
    def all_classes(self) -> List[BaksmaliClass]:
        """返回全量类列表。"""
        return list(self._classes)

    # ─────────────────────── smali 格式输出 ───────────────────────

    def format_method_baksmali(self, m: BaksmaliMethod) -> str:
        """生成 baksmali 风格 smali 文本（.method 头 + 寄存器 + .end method）。"""
        lines: List[str] = []
        flags = _access_flags_to_str(m.access_flags)
        flags_str = f"{flags} " if flags else ""
        descriptor = m.descriptor or "()V"
        lines.append(f"    .method {flags_str}{m.name}{descriptor}")
        lines.append(f"        .registers {m.registers_size}")
        # 参数列表
        if m.descriptor.startswith("("):
            param_types = _parse_param_types(m.descriptor)
            param_count = len(param_types)
            reg_start = m.registers_size - param_count if param_count <= m.registers_size else 0
            for p_idx, p_type in enumerate(param_types):
                reg = reg_start + p_idx
                lines.append(f"        .param p{reg}, \"param{p_idx}\"    # {p_type}")
        if m.tries_size > 0:
            lines.append(f"        # {m.tries_size} try/catch block(s)")
        if m.insns and len(m.insns) >= 4:
            lines.append(f"        # {m.code_item_size // 2} instruction(s)")
            # 输出前几条指令的 hex 预览
            hex_preview = m.insns[:min(32, len(m.insns))].hex(" ")
            lines.append(f"        # insns: {hex_preview}")
        lines.append(f"        .locals {m.ins_size}")
        lines.append(f"    .end method")
        return "\n".join(lines)

    def format_class_baksmali(self, cls: BaksmaliClass) -> str:
        """生成完整类的 smali 文本。"""
        lines: List[str] = []
        lines.append(f".class {_access_flags_to_str(cls.access_flags)} {cls.class_name}")
        lines.append(f".super {cls.super_class or 'Ljava/lang/Object;'}")
        if cls.source_file:
            lines.append(f".source \"{cls.source_file}\"")
        lines.append("")

        # 字段
        for f_name, f_type, f_access in cls.static_fields:
            lines.append(f".field {_access_flags_to_str(f_access)} {f_name}:{f_type}")
        for f_name, f_type, f_access in cls.instance_fields:
            lines.append(f".field {_access_flags_to_str(f_access)} {f_name}:{f_type}")
        if cls.static_fields or cls.instance_fields:
            lines.append("")

        # 方法
        for m in cls.methods:
            lines.append(self.format_method_baksmali(m))
            lines.append("")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# 辅助函数
# ─────────────────────────────────────────────────────────────

def _java_to_internal(java_name: str) -> str:
    """com.pkg.Cls → Lcom/pkg/Cls;"""
    return "L" + java_name.replace(".", "/") + ";"


def _type_to_descriptor(internal: str) -> str:
    """将 Lcom/pkg/Cls; 转为字段描述符（已经是 DEX 内部格式则原样返回）。"""
    if not internal:
        return "V"
    # 已经是类型描述符格式
    if internal.startswith("L") or internal.startswith("[") or internal in (
        "V", "Z", "B", "S", "C", "I", "J", "F", "D",
    ):
        return internal
    # 基本类型映射
    return {
        "void": "V", "boolean": "Z", "byte": "B", "short": "S",
        "char": "C", "int": "I", "long": "J", "float": "F", "double": "D",
    }.get(internal, "Ljava/lang/Object;")


def _parse_param_types(descriptor: str) -> List[str]:
    """解析方法描述符 (Ljava/lang/String;I)Ljava/lang/String; 中的参数类型列表。"""
    if not descriptor.startswith("("):
        return []
    end = descriptor.find(")")
    if end == -1:
        return []
    args_str = descriptor[1:end]
    types: List[str] = []
    i = 0
    while i < len(args_str):
        ch = args_str[i]
        if ch == "L":
            semi = args_str.find(";", i)
            if semi == -1:
                types.append(args_str[i:])
                break
            types.append(args_str[i:semi + 1])
            i = semi + 1
        elif ch == "[":
            # 数组类型：找到基本类型
            j = i + 1
            while j < len(args_str) and args_str[j] == "[":
                j += 1
            if j < len(args_str):
                if args_str[j] == "L":
                    semi = args_str.find(";", j)
                    if semi == -1:
                        types.append(args_str[i:])
                        break
                    types.append(args_str[i:semi + 1])
                    i = semi + 1
                else:
                    types.append(args_str[i:j + 1])
                    i = j + 1
            else:
                types.append(args_str[i:])
                break
        else:
            types.append(ch)
            i += 1
    return types


# DEX 访问标志常量（简集）
_ACC_PUBLIC = 0x1
_ACC_PRIVATE = 0x2
_ACC_PROTECTED = 0x4
_ACC_STATIC = 0x8
_ACC_FINAL = 0x10
_ACC_INTERFACE = 0x200
_ACC_ABSTRACT = 0x400
_ACC_SYNTHETIC = 0x1000
_ACC_ANNOTATION = 0x2000
_ACC_ENUM = 0x4000
_ACC_CONSTRUCTOR = 0x10000
_ACC_DECLARED_SYNCHRONIZED = 0x20000


def _access_flags_to_str(flags: int) -> str:
    """将访问标志整数转为 Java 修饰符字符串。"""
    parts: List[str] = []
    if flags & _ACC_PUBLIC:
        parts.append("public")
    if flags & _ACC_PRIVATE:
        parts.append("private")
    if flags & _ACC_PROTECTED:
        parts.append("protected")
    if flags & _ACC_STATIC:
        parts.append("static")
    if flags & _ACC_FINAL:
        parts.append("final")
    if flags & _ACC_ABSTRACT:
        parts.append("abstract")
    if flags & _ACC_SYNTHETIC:
        parts.append("synthetic")
    if flags & _ACC_CONSTRUCTOR:
        parts.append("constructor")
    return " ".join(parts)


# ─────────────────────────────────────────────────────────────
# 便捷函数：从 DEX 字节直接产出 smali 文本
# ─────────────────────────────────────────────────────────────

def dex_to_smali(dex_bytes: bytes, max_classes: int = 500) -> str:
    """一次性将 DEX 字节转为 smali 文本（完整类列表）。

    :param dex_bytes: DEX 文件字节
    :param max_classes: 限制最多输出的类数量（防止大 APK 输出爆炸）
    :return: 完整 smali 文本（多类拼接，用空行分隔）
    """
    if not dex_bytes or len(dex_bytes) < 112:
        return "# (empty or invalid DEX: too short)"
    parser = DexBaksmali()
    try:
        parser.parse_dex(dex_bytes)
    except ValueError as exc:
        return f"# (DEX parse failed: {exc})"
    parts: List[str] = []
    for i, cls in enumerate(parser.all_classes):
        if i >= max_classes:
            parts.append(f"\n# ... ({len(parser.all_classes) - i} more classes truncated)")
            break
        parts.append(parser.format_class_baksmali(cls))
    return "\n".join(parts) if parts else "# (empty DEX)"
