"""应用配置。

设计要点：
- 用 pydantic-settings 把环境变量 / .env 映射成**带类型、带默认值**的对象，
  避免到处写 os.getenv("...") 并手工转换类型。
- 密钥（如 DEEPSEEK_API_KEY）只从环境变量注入，绝不硬编码进源码。
- 这个模块只依赖 pydantic，不依赖任何业务代码，因此可以被任何层安全导入。
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # model_config 是 pydantic-settings 的运行时配置：
    #   env_file      —— 启动时自动读取项目根目录的 .env（不存在也不报错）
    #   case_sensitive —— 环境变量名大小写不敏感，DEEPSEEK_API_KEY 和 deepseek_api_key 都认
    #   extra="ignore" —— .env 里出现本类没声明的变量时忽略，而不是抛异常
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── 应用 ────────────────────────────────────────────────
    APP_ENV: str = "development"  # development | production，用于区分运行环境
    APP_PORT: int = 8000  # uvicorn 监听端口

    # ── 存储 ────────────────────────────────────────────────
    # 注意驱动是 asyncpg（异步），因为整个后端是 async 的，不能用同步 psycopg
    DATABASE_URL: str = (
        "postgresql+asyncpg://netsentinel:netsentinel@localhost:5432/netsentinel"
    )
    REDIS_URL: str = "redis://localhost:6379/0"  # 0 号库，后续放告警总线与缓存

    # ── LLM ─────────────────────────────────────────────────
    # 默认空字符串：没配 key 时程序仍能启动（便于跑测试），真正调用时再校验
    DEEPSEEK_API_KEY: str = "sk-29b1ac12c3c0475da1b3fd19364a4cce"
    DEEPSEEK_BASE_URL: str = "https://api.deepseek.com"
    TRIAGE_MODEL: str = "deepseek-chat"  # L1 分诊用便宜快模型
    INVESTIGATION_MODEL: str = "deepseek-reasoner"  # L2 深度调查用强推理模型

    # ── 研判策略 ────────────────────────────────────────────
    # 决定一条告警是否从 L1 升级到 L2：严重度 >= 该值，或置信度 < 该阈值
    ESCALATE_MIN_SEVERITY: str = "high"
    ESCALATE_MAX_CONFIDENCE: int = 60
    DEDUP_TTL_SECONDS: int = 60  # 同一 (源IP, 签名) 在该窗口内只算一条，防告警风暴


# 模块级单例：全项目共享同一份配置，避免重复解析
settings = Settings()
