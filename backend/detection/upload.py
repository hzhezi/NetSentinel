"""pcap 上传处理：校验、落盘、清理。

═══════════════════════════════════════════════════════════════════
三个安全考量（都是必需的，不是过度设计）
═══════════════════════════════════════════════════════════════════

① **扩展名白名单**
    只接受 .pcap / .pcapng。不做校验的话，这个接口就是一个
    "上传任意文件到服务器"的入口。

② **落盘用随机文件名**
    ⚠️ 不能直接用用户提供的文件名：
        用户传 `../../etc/passwd` 就会写到预期目录之外（路径穿越）。
        必须用随机名 + 只保留扩展名。

③ **大小上限**
    防止有人上传几十 GB 的文件把磁盘打满。

═══════════════════════════════════════════════════════════════════
流式写盘
═══════════════════════════════════════════════════════════════════
FastAPI 的 UploadFile 本身就是流式对象，用 shutil.copyfileobj
边读边写 —— 而不是 `await file.read()` 一次性读进内存。
后者在 50MB 文件上会白占 50MB 内存，且不可扩展。
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from fastapi import UploadFile

from backend.core.exceptions import ValidationError

# 只接受这两种 pcap 格式
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

# 上限 50MB：演示用的小 pcap 通常几 KB 到几 MB，
# 50MB 是很宽松的上限，同时避免磁盘被大文件打满。
MAX_UPLOAD_BYTES = 50 * 1024 * 1024


def validate_upload(upload: UploadFile) -> None:
    """校验上传的文件（扩展名与文件名）。

    大小校验在落盘时做（需要边写边数，见 save_upload）。

    Raises:
        ValidationError: 校验不通过
    """
    filename = (upload.filename or "").strip()
    if not filename:
        raise ValidationError("上传文件缺少文件名")

    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        allowed = " / ".join(sorted(ALLOWED_EXTENSIONS))
        raise ValidationError(f"不支持的文件类型 {suffix or '(无扩展名)'}，仅接受 {allowed} 格式")


async def save_upload(upload: UploadFile, dest_dir: Path) -> Path:
    """把上传的文件写入目标目录，返回落盘路径。

    ⚠️ 文件名用随机 UUID 生成，**不使用用户提供的名字** ——
    否则 `../../x.pcap` 这类文件名会写到目标目录之外。

    边写边统计大小，超过上限则中止并删除半成品文件。
    """
    dest_dir.mkdir(parents=True, exist_ok=True)

    # 只保留扩展名，文件名随机 —— 这是防路径穿越的关键
    suffix = Path(upload.filename or "x").suffix.lower()
    dest = dest_dir / f"{uuid.uuid4().hex}{suffix}"

    written = 0
    with open(dest, "wb") as out:
        # 分块读取并写盘：避免把整个文件读进内存
        while chunk := await upload.read(1024 * 1024):  # 每次 1MB
            written += len(chunk)
            if written > MAX_UPLOAD_BYTES:
                out.close()
                dest.unlink(missing_ok=True)
                raise ValidationError(f"文件超过大小上限 ({MAX_UPLOAD_BYTES // 1024 // 1024}MB)")
            out.write(chunk)

    # 空文件没有分析价值，提前拒绝（也让错误更早暴露）
    if written == 0:
        dest.unlink(missing_ok=True)
        raise ValidationError("上传的文件为空")

    return dest


def cleanup(*paths: Path) -> None:
    """删除临时文件。

    静默失败（missing_ok）—— 清理不该因为文件已被删而抛异常，
    否则一次清理失败可能让整个请求返回 500。
    """
    for p in paths:
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass


def cleanup_dir(directory: Path) -> None:
    """删除临时目录及其中内容（用于处理结束后的整体清理）。"""
    try:
        shutil.rmtree(directory, ignore_errors=True)
    except OSError:
        pass
