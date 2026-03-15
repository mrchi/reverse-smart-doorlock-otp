import datetime

import pytest

from generate_totp import generate_totp

# 固定测试时间：2026-03-13 01:05:42
TEST_TIME = datetime.datetime(2026, 3, 13, 1, 5, 42)
ADMIN_PASSWORD = 123456


@pytest.mark.parametrize(
    "duration, expected_password",
    [
        (5, "3379340005"),
        (10, "1418887010"),
        (20, "2591217020"),
        (30, "9436463030"),
        (40, "1732001040"),
        (50, "6474356050"),
        (60, "2574544060"),
    ],
)
def test_totp_generation(duration, expected_password):
    """测试不同有效期的 TOTP 密码生成"""
    result = generate_totp(ADMIN_PASSWORD, duration, TEST_TIME)
    assert result == expected_password, (
        f"有效期{duration}分钟的密码生成错误：预期{expected_password}，实际得到{result}"
    )
