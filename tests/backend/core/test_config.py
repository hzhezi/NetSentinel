"""配置模块的测试。

这里体现 TDD 的一个常见技巧：所有测试都传 `_env_file=None`，
目的是**屏蔽开发者本机的 .env**，否则测试结果会随本机配置漂移。
"""

from backend.core.config import Settings


def test_settings_defaults():
    """不提供任何环境变量时，应落到代码里写死的默认值。"""
    s = Settings(_env_file=None)
    assert s.APP_ENV == "development"
    assert s.TRIAGE_MODEL == "deepseek-chat"
    assert s.ESCALATE_MIN_SEVERITY == "high"


def test_settings_reads_env(monkeypatch):
    """环境变量应能覆盖默认值。

    monkeypatch.setenv 由 pytest 提供，测试结束后会自动还原，
    不会污染其他测试。
    """
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    s = Settings(_env_file=None)
    assert s.DEEPSEEK_API_KEY == "sk-test"
