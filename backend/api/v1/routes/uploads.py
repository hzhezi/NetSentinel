"""pcap 上传与检测 API。

═══════════════════════════════════════════════════════════════════
流程
═══════════════════════════════════════════════════════════════════
    上传 .pcap
        ↓ validate_upload（扩展名校验）
        ↓ save_upload（流式落盘，随机文件名防路径穿越）
    临时 pcap
        ↓ analyze_pcap（调 Suricata 容器检测）
    eve.json
        ↓ run_replay（复用既有重放链路）
    告警落库 + WebSocket 推送
        ↓ cleanup（删除临时文件）
    done

**同步执行**：单个 pcap 的检测+重放通常在几十秒内（我们的测试流量
毫秒级）。虽然比普通请求慢，但用户上传后**期望看到结果**，
同步返回比"丢后台任务 + 轮询"体验更直接。
若将来支持大文件，应改为后台任务 + 进度推送。

═══════════════════════════════════════════════════════════════════
安全与资源
═══════════════════════════════════════════════════════════════════
- 扩展名白名单（只接受 pcap/pcapng）
- 50MB 上限
- 随机文件名（防路径穿越）
- **用完即删**（不保留上传历史：磁盘不堆积、隐私更干净）
- 失败路径也清理（否则失败的上传会堆积）
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import uuid
from pathlib import Path

import structlog
from fastapi import APIRouter, File, UploadFile
from pydantic import BaseModel

from backend.api.websocket.manager import ws_manager
from backend.core.database import AsyncSessionLocal
from backend.core.exceptions import UpstreamError
from backend.detection.suricata_runner import SuricataError, analyze_pcap
from backend.detection.upload import cleanup_dir, save_upload, validate_upload
from backend.repositories import suppression_repository as sup_repo
from backend.services.suppression import SuppressionService
from backend.workers.replay import run_replay

log = structlog.get_logger(__name__)

router = APIRouter()

# 上传根目录。测试通过 monkeypatch 替换它。
UPLOAD_ROOT = Path("data/uploads")

# 重放用的 session 工厂。提成模块级变量是为了**可测试** ——
# 测试注入指向临时 schema 的工厂，就能验证落库结果。
# （若写死在函数里用 AsyncSessionLocal，测试会写到开发库、查不到数据）
SESSION_FACTORY = AsyncSessionLocal


class UploadResult(BaseModel):
    """上传处理结果。"""

    status: str
    message: str
    alerts_created: int
    deduplicated: int
    suppressed: int
    errors: int


@router.post("/pcap", response_model=UploadResult)
async def upload_pcap(
    file: UploadFile = File(..., description="待检测的 pcap / pcapng 文件"),
) -> UploadResult:
    """上传 pcap，自动检测并重放。

    处理完成后临时文件被删除，只返回结果摘要。
    """
    # ── 1. 校验 ──
    validate_upload(file)

    # 每次上传用独立目录，便于整体清理（也避免并发上传互相干扰）
    task_dir = UPLOAD_ROOT / uuid.uuid4().hex
    pcap_path: Path | None = None

    try:
        # ── 2. 落盘 ──
        pcap_path = await save_upload(file, task_dir)
        log.info("pcap_uploaded", size=pcap_path.stat().st_size)

        # ── 3. Suricata 检测 ──
        try:
            eve_path = await analyze_pcap(pcap_path, task_dir)
        except SuricataError as exc:
            # 用 502（上游依赖失败）而非 500 —— Docker 是外部依赖，
            # 且错误信息会明确告诉用户"请确认 Docker 已启动"
            raise UpstreamError(str(exc)) from exc

        # ── 4. 重放 ──
        # 加载抑制规则（与 feeds 路由一致：每次重新加载保证规则最新）
        async with SESSION_FACTORY() as session:
            rules = await sup_repo.load_domain_rules(session)
        suppressions = SuppressionService(rules=rules)

        result = await run_replay(
            eve_path=eve_path,
            # 上传检测的场景不需要"演示节奏"，全速处理即可
            speed=1_000_000,
            session_factory=SESSION_FACTORY,
            on_alert=ws_manager.broadcast,
            suppressions=suppressions,
        )

        return UploadResult(
            status="completed",
            message=(
                f"处理完成：检测到 {result['emitted']} 条告警"
                + (f"，去重 {result['deduplicated']} 条" if result["deduplicated"] else "")
                + (f"，抑制 {result['suppressed']} 条" if result["suppressed"] else "")
            ),
            alerts_created=result["emitted"],
            deduplicated=result["deduplicated"],
            suppressed=result["suppressed"],
            errors=result["errors"],
        )

    finally:
        # ── 5. 清理 ──
        # 放 finally：无论成功、校验失败还是检测失败都要清 ——
        # 否则失败的上传会一直堆在磁盘上。
        # 整个任务目录一起删（pcap + eve.json 都在里面）
        cleanup_dir(task_dir)


@router.get("/limits")
async def get_limits() -> dict:
    """返回上传限制，供前端提示用户。

    前端据此显示"最大 50MB、仅支持 pcap/pcapng"，
    而不是等用户传错了才报错。
    """
    from backend.detection.upload import ALLOWED_EXTENSIONS, MAX_UPLOAD_BYTES

    return {
        "max_bytes": MAX_UPLOAD_BYTES,
        "max_mb": MAX_UPLOAD_BYTES // 1024 // 1024,
        "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
    }
