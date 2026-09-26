"""数据流控制 API：启动/查看重放。

重放是长时任务，因此放在后台执行，接口立即返回 ——
否则 HTTP 请求会挂住几分钟（甚至因 Nginx/浏览器超时而断）。
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel, Field

from backend.core.database import AsyncSessionLocal
from backend.core.exceptions import ValidationError
from backend.workers.replay import run_replay

router = APIRouter()

# 允许重放的目录白名单（相对项目根）。
# 用白名单而非直接接受任意路径：避免 API 被用来读取系统任意文件
# （路径穿越）。虽是小项目，但这是低成本的基本防护。
_ALLOWED_DIRS = (Path("data"),)


class ReplayRequest(BaseModel):
    eve_path: str = Field(description="eve.json 路径（相对项目根）")
    speed: float = Field(default=50.0, gt=0, description="重放倍速")
    max_delay: float | None = Field(default=None, description="单步等待上限（秒）")


class ReplayResponse(BaseModel):
    status: str
    message: str


def _validate_path(eve_path: str) -> Path:
    """校验路径在允许范围内，防止路径穿越。"""
    p = Path(eve_path).resolve()
    root = Path.cwd().resolve()
    if not any(
        (root / d).resolve() in p.parents or p == (root / d).resolve() for d in _ALLOWED_DIRS
    ):
        raise ValidationError(f"路径不在允许范围内（仅限 {_ALLOWED_DIRS}）: {eve_path}")
    return p


async def _replay_task(eve_path: Path, speed: float, max_delay: float | None) -> None:
    """后台重放任务。

    推送用 ws_manager.broadcast —— 这里是**唯一**把 worker 的
    回调与具体推送方式绑定的地方（worker 本身不依赖 WebSocket）。
    """
    from backend.api.websocket.manager import ws_manager

    await run_replay(
        eve_path=eve_path,
        speed=speed,
        max_delay=max_delay,
        session_factory=AsyncSessionLocal,
        on_alert=ws_manager.broadcast,
    )


@router.post("/replay", response_model=ReplayResponse)
async def start_replay(req: ReplayRequest, background: BackgroundTasks):
    """启动 eve.json 重放（后台执行，立即返回）。"""
    path = _validate_path(req.eve_path)
    if not path.exists():
        raise ValidationError(f"文件不存在: {req.eve_path}")

    background.add_task(_replay_task, path, req.speed, req.max_delay)
    return ReplayResponse(
        status="started",
        message=f"重放已启动: {req.eve_path}（倍速 {req.speed}x）",
    )


@router.get("/available")
async def list_available() -> dict:
    """列出可用于重放的 eve.json 文件，供前端下拉选择。"""
    files: list[str] = []
    for d in _ALLOWED_DIRS:
        base = Path(d)
        if base.exists():
            files.extend(str(p) for p in base.rglob("*.json") if p.is_file())
    return {"files": sorted(files)}
