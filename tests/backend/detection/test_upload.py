"""pcap 上传与检测的测试。

═══════════════════════════════════════════════════════════════════
流程
═══════════════════════════════════════════════════════════════════
    用户上传 .pcap
        ↓ 校验（扩展名、大小）
    存到临时目录
        ↓ 调 Suricata 处理（subprocess）
    产出 eve.json
        ↓ 触发重放（复用 run_replay）
    告警流出 → LLM 研判
        ↓ 清理（删除上传的 pcap 与临时 eve.json）

═══════════════════════════════════════════════════════════════════
设计要点
═══════════════════════════════════════════════════════════════════
① **用完即删**
    上传的文件不保留 —— 磁盘不堆积、隐私更干净、无需管理上传历史。

② **Suricata 调用可注入**
    测试不能依赖 Docker/Suricata（CI 环境未必有）。
    通过依赖注入把"检测"这一步替换掉，测试只验证编排逻辑。

③ **流式写盘，不读进内存**
    50MB 的 pcap 读进内存再写盘是浪费；应边收边写。
    （FastAPI 的 UploadFile 本身就是流式的，用 shutil.copyfileobj）
═══════════════════════════════════════════════════════════════════
"""


import pytest
from fastapi import UploadFile

from backend.core.exceptions import ValidationError
from backend.detection.upload import (
    ALLOWED_EXTENSIONS,
    MAX_UPLOAD_BYTES,
    save_upload,
    validate_upload,
)


def _fake_upload(filename: str, size: int = 1024) -> UploadFile:
    """构造上传文件对象。

    用 starlette 真实的 UploadFile 而非手写假对象 ——
    手写的假对象容易漏方法（第一次就漏了 read），
    而真实类型能保证接口一致。
    """
    import io

    from starlette.datastructures import UploadFile as StarletteUploadFile

    return StarletteUploadFile(file=io.BytesIO(b"x" * size), filename=filename)


# ── 校验 ───────────────────────────────────────────────────────


def test_accepts_pcap_extension():
    validate_upload(_fake_upload("traffic.pcap"))


def test_accepts_pcapng_extension():
    """pcapng 是 pcap 的新一代格式，同样应接受。"""
    validate_upload(_fake_upload("traffic.pcapng"))


def test_rejects_unknown_extension():
    """只接受 pcap 格式 —— 防止用户上传任意文件。

    报错信息要明确列出允许的扩展名，便于用户改正。
    """
    with pytest.raises(ValidationError) as exc:
        validate_upload(_fake_upload("malware.exe"))
    assert "pcap" in str(exc.value).lower()


def test_rejects_empty_filename():
    with pytest.raises(ValidationError):
        validate_upload(_fake_upload(""))


def test_extension_check_is_case_insensitive():
    """`.PCAP` 也应被接受（用户不一定小写）。"""
    validate_upload(_fake_upload("TRAFFIC.PCAP"))


def test_allowed_extensions_content():
    assert ".pcap" in ALLOWED_EXTENSIONS
    assert ".pcapng" in ALLOWED_EXTENSIONS


def test_max_size_is_reasonable():
    """上限应在一个合理范围 —— 太小演示不够，太大浪费磁盘。

    这里只锁住量级（1MB ~ 500MB），具体值可调整。
    """
    assert 1 * 1024 * 1024 <= MAX_UPLOAD_BYTES <= 500 * 1024 * 1024


# ── 落盘 ───────────────────────────────────────────────────────


async def test_save_upload_writes_file(tmp_path):
    """上传内容应写入临时目录，且文件名被规范化。

    ⚠️ 不能用用户提供的文件名直接落盘：
        `../../etc/passwd` 这类路径会跑到预期目录之外（路径穿越）。
        因此落盘时用随机文件名 + 保留原扩展名。
    """
    upload = _fake_upload("traffic.pcap", size=2048)
    path = await save_upload(upload, tmp_path)

    assert path.exists()
    assert path.stat().st_size == 2048
    assert path.suffix == ".pcap"
    # 文件名必须是随机生成的，不含原始名（防穿越）
    assert "traffic" not in path.name


async def test_save_upload_handles_path_traversal(tmp_path):
    """恶意文件名不得写到目标目录之外。"""
    upload = _fake_upload("../../evil.pcap", size=10)
    path = await save_upload(upload, tmp_path)

    # 落盘位置必须在 tmp_path 内
    assert path.parent.resolve() == tmp_path.resolve()


async def test_save_upload_unique_names(tmp_path):
    """两次上传同名文件不应互相覆盖。"""
    p1 = await save_upload(_fake_upload("a.pcap", 10), tmp_path)
    p2 = await save_upload(_fake_upload("a.pcap", 10), tmp_path)
    assert p1 != p2


async def test_save_upload_preserves_content(tmp_path):
    """写入的字节应与上传的完全一致（不能损坏流量数据）。"""
    import io

    from starlette.datastructures import UploadFile as StarletteUploadFile

    data = b"\xd4\xc3\xb2\xa1" + b"\x00" * 100  # 模拟 pcap 魔数 + 内容
    upload = StarletteUploadFile(file=io.BytesIO(data), filename="x.pcap")
    path = await save_upload(upload, tmp_path)

    assert path.read_bytes() == data
