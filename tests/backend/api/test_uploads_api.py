"""pcap 上传 API 的测试。

完整流程：上传 pcap → 校验 → 落盘 → Suricata 检测 → 重放 → 清理。

测试用**注入的假 Suricata runner**，因此不依赖 Docker。
真实调用由人工验证（见 docs/demo-script.md）。
"""


import pytest
from httpx import ASGITransport, AsyncClient

from backend.api.v1.routes import uploads as uploads_route
from backend.core.database import get_session
from backend.main import create_app
from backend.repositories import alert_repository as alert_repo


@pytest.fixture
def app(pg_session, tmp_path, monkeypatch):
    """构造应用，把上传目录与重放逻辑都指向可测的实现。"""
    # 上传目录指向临时路径
    monkeypatch.setattr(uploads_route, "UPLOAD_ROOT", tmp_path / "uploads")

    # session 工厂指向测试的临时 schema —— 否则重放会写到开发库，测试查不到数据
    class _Ctx:
        def __init__(self, session):
            self._session = session

        async def __aenter__(self):
            return self._session

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(uploads_route, "SESSION_FACTORY", lambda: _Ctx(pg_session))

    # 假的 Suricata：直接写一份 eve.json（内容与文件对应）
    async def fake_analyze(pcap_path, work_dir, **kwargs):
        work_dir.mkdir(parents=True, exist_ok=True)
        eve = work_dir / "eve.json"
        eve.write_text(_eve_content(), encoding="utf-8")
        return eve

    monkeypatch.setattr(uploads_route, "analyze_pcap", fake_analyze)

    application = create_app()

    async def _override():
        yield pg_session

    application.dependency_overrides[get_session] = _override
    return application


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def _eve_content() -> str:
    import json

    return json.dumps(
        {
            "timestamp": "2017-07-05T10:00:00+0000",
            "event_type": "alert",
            "src_ip": "45.33.32.156",
            "dest_ip": "192.168.10.5",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature": "Possible SQL Injection (UNION SELECT)",
                "signature_id": 1000001,
                "category": "Web Application Attack",
                "severity": 1,
            },
        }
    )


def _pcap_file(name: str = "test.pcap", size: int = 512) -> tuple[str, bytes, str]:
    """构造 multipart 上传用的文件元组。"""
    return (name, b"\xd4\xc3\xb2\xa1" + b"\x00" * size, "application/octet-stream")


# ── 正常路径 ───────────────────────────────────────────────────


async def test_upload_and_detect_pcap(client, pg_session):
    """上传 pcap → 检测 → 重放 → 告警落库。"""
    r = await client.post(
        "/api/v1/uploads/pcap",
        files={"file": _pcap_file()},
    )
    assert r.status_code == 200
    body = r.json()

    assert body["status"] == "completed"
    assert body["alerts_created"] == 1
    # 摘要消息报告条数；具体告警内容在列表/详情页查看
    assert "1 条告警" in body["message"]

    # 确认真的落库了
    _, total = await alert_repo.list_alerts(pg_session)
    assert total == 1


async def test_response_reports_dedup_and_suppressed(client):
    """响应要报告去重/抑制的数量 —— 用户想知道"为什么告警变少了"。"""
    r = await client.post("/api/v1/uploads/pcap", files={"file": _pcap_file()})
    body = r.json()

    assert "deduplicated" in body
    assert "suppressed" in body
    assert "errors" in body


# ── 校验失败 ───────────────────────────────────────────────────


async def test_rejects_non_pcap(client):
    """非 pcap 文件被拒绝（不进入检测流程）。"""
    r = await client.post(
        "/api/v1/uploads/pcap",
        files={"file": ("bad.exe", b"MZ\x90\x00", "application/octet-stream")},
    )
    assert r.status_code == 422
    assert r.json()["code"] == "VALIDATION_ERROR"


async def test_rejects_empty_file(client):
    r = await client.post(
        "/api/v1/uploads/pcap",
        files={"file": ("empty.pcap", b"", "application/octet-stream")},
    )
    assert r.status_code == 422


async def test_accepts_pcapng(client):
    """pcapng 格式同样接受。"""
    r = await client.post(
        "/api/v1/uploads/pcap",
        files={
            "file": ("t.pcapng", b"\x0a\x0d\x0d\x0a" + b"\x00" * 100, "application/octet-stream")
        },
    )
    assert r.status_code == 200


# ── 检测失败 ───────────────────────────────────────────────────


async def test_detection_failure_returns_clear_error(client, monkeypatch):
    """Suricata 不可用时应给出明确提示，而不是笼统的 500。

    这对应真实场景：用户没启动 Docker。
    """
    from backend.detection.suricata_runner import SuricataError

    async def failing_analyze(pcap_path, work_dir, **kwargs):
        raise SuricataError("未找到 docker 命令。请确认 Docker Desktop 已启动。")

    monkeypatch.setattr(uploads_route, "analyze_pcap", failing_analyze)

    r = await client.post("/api/v1/uploads/pcap", files={"file": _pcap_file()})
    # 502（上游依赖失败）比 500 更准确 —— Docker 是外部依赖
    assert r.status_code == 502
    assert "Docker" in r.json()["message"]


# ── 清理 ───────────────────────────────────────────────────────


async def test_temp_files_cleaned_up(client, tmp_path, monkeypatch):
    """上传的文件与中间产物在处理完后应被删除。

    设计取舍：不保留上传历史 —— 磁盘不堆积、隐私更干净。
    """
    upload_root = tmp_path / "uploads"
    monkeypatch.setattr(uploads_route, "UPLOAD_ROOT", upload_root)

    r = await client.post("/api/v1/uploads/pcap", files={"file": _pcap_file()})
    assert r.status_code == 200

    # 任务目录应为空（或不存在）
    if upload_root.exists():
        remaining = list(upload_root.rglob("*.pcap")) + list(upload_root.rglob("*.json"))
        assert remaining == [], f"临时文件未清理: {remaining}"


async def test_cleanup_happens_even_on_detection_failure(client, tmp_path, monkeypatch):
    """检测失败时也要清理 —— 否则失败的上传会一直堆在磁盘上。"""
    from backend.detection.suricata_runner import SuricataError

    upload_root = tmp_path / "uploads"
    monkeypatch.setattr(uploads_route, "UPLOAD_ROOT", upload_root)

    async def failing_analyze(pcap_path, work_dir, **kwargs):
        raise SuricataError("模拟失败")

    monkeypatch.setattr(uploads_route, "analyze_pcap", failing_analyze)

    r = await client.post("/api/v1/uploads/pcap", files={"file": _pcap_file()})
    assert r.status_code == 502

    if upload_root.exists():
        remaining = list(upload_root.rglob("*.pcap"))
        assert remaining == [], f"失败后未清理: {remaining}"


# ── 没有文件 ───────────────────────────────────────────────────


async def test_missing_file_returns_422(client):
    """没传文件时应返回明确的校验错误。"""
    r = await client.post("/api/v1/uploads/pcap")
    assert r.status_code == 422
