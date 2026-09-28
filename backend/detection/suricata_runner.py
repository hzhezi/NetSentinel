"""调用 Suricata 分析 pcap。

═══════════════════════════════════════════════════════════════════
为什么通过 Docker 调用
═══════════════════════════════════════════════════════════════════
Suricata 是 Linux 网络工具，在 macOS 上装起来麻烦（版本旧、依赖多）。
用容器调用可以：
    - 跨平台（后端跑在宿主机也能调 Linux 容器）
    - 依赖隔离（Suricata 的系统库封在镜像里）
    - 无需特权（离线 -r 模式不需要 NET_RAW）

后端跑在宿主机时，直接 subprocess 调 `docker compose run` 即可 ——
不需要挂 docker.sock（那是"容器调容器"才要处理的问题）。

═══════════════════════════════════════════════════════════════════
可注入设计（为了可测）
═══════════════════════════════════════════════════════════════════
真正的 subprocess 调用依赖 Docker 环境，CI 里未必有。
因此把"执行命令"抽成可替换的 runner：
    - 生产：subprocess 调 docker compose
    - 测试：注入一个假 runner，只验证命令拼装与错误处理
═══════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Awaitable, Callable
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)

# 单次检测的超时（秒）。大 pcap 处理较慢，但也不该无限等待。
DEFAULT_TIMEOUT = 300


class SuricataError(Exception):
    """Suricata 执行失败。

    单独定义以便上层区分"检测环境不可用"与"业务逻辑错误" ——
    前者应给用户明确提示（如"请确认 Docker 正在运行"），
    而不是一个笼统的 500。
    """


async def _run_command(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """执行命令并返回 (返回码, stdout, stderr)。默认实现。"""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        raise SuricataError(f"Suricata 处理超时（{timeout} 秒）") from None
    return (
        proc.returncode or 0,
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )


def docker_available() -> bool:
    """检查 docker 命令是否存在。

    提前检查而不是等到执行时才失败：能给出更明确的提示。
    """
    return shutil.which("docker") is not None


async def analyze_pcap(
    pcap_path: Path,
    work_dir: Path,
    *,
    runner: Callable[[list[str], int], Awaitable[tuple[int, str, str]]] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> Path:
    """用 Suricata 分析 pcap，返回产出的 eve.json 路径。

    Args:
        pcap_path: 待分析的 pcap（宿主机路径）。
        work_dir: 输出目录（宿主机路径，会挂载进容器）。
        runner: 可注入的命令执行器（测试用）。
        timeout: 超时秒数。

    Raises:
        SuricataError: Docker 不可用 / 执行失败 / 未产出 eve.json
    """
    run = runner or _run_command

    if runner is None and not docker_available():
        raise SuricataError("未找到 docker 命令。请确认 Docker Desktop 已启动。")

    work_dir.mkdir(parents=True, exist_ok=True)
    eve_path = work_dir / "eve.json"
    # 清掉可能存在的旧输出，避免读到上一次的结果
    eve_path.unlink(missing_ok=True)

    # ── 拼装命令 ──
    # 把 pcap 所在目录挂到容器的 /input，输出目录挂到 /output。
    # 用目录挂载而非单文件挂载：单文件挂载在某些平台（macOS）有 inode 问题。
    pcap_dir = pcap_path.parent.resolve()
    out_dir = work_dir.resolve()

    cmd = [
        "docker",
        "compose",
        "--profile",
        "suricata",
        "run",
        "--rm",
        "-v",
        f"{pcap_dir}:/input:ro",
        "-v",
        f"{out_dir}:/output",
        "--entrypoint",
        "suricata",
        "suricata",
        "-r",
        f"/input/{pcap_path.name}",
        "-l",
        "/output",
    ]

    log.info("suricata_analyze_start", pcap=pcap_path.name)
    returncode, stdout, stderr = await run(cmd, timeout)

    if returncode != 0:
        # 把 stderr 带进异常信息 —— 排查时需要它
        raise SuricataError(
            f"Suricata 执行失败（返回码 {returncode}）：{stderr[-500:] or stdout[-500:]}"
        )

    if not eve_path.exists():
        # Suricata 可能因规则/配置问题没产出文件（但仍返回 0）
        raise SuricataError("Suricata 执行完成但未产出 eve.json —— 可能是配置或规则文件有问题")

    log.info("suricata_analyze_done", eve=eve_path.name, size=eve_path.stat().st_size)
    return eve_path
