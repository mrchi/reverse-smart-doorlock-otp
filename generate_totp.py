#!/usr/bin/env python3
import argparse
import calendar
import datetime
import hashlib
import hmac
import struct
import sys

# 常量定义
PASSWORD_MAIN_LENGTH: int = 8  # 主密码长度（固定8位，与小程序版本兼容）
DURATION_LENGTH: int = 2  # 有效期位数（固定2位，与小程序版本兼容）
# 时间计算起点（与原实现保持一致，2000 年 1 月 1 日 0 点，时区无关）
EPOCH: datetime.datetime = datetime.datetime(2000, 1, 1, tzinfo=None)


def generate_digit_password(seed_int: int, time_counter: int) -> str:
    """根据种子密码和时间计数器生成指定长度的数字密码，保持与原实现完全兼容"""
    # 根据管理员密码和 time counter 计算 HMAC-SHA1，生成 20 个字节长度的 list
    hmac_result = list(
        hmac.new(
            struct.pack("<I", seed_int), struct.pack("<I", time_counter), hashlib.sha1
        ).digest()
    )

    # 取最后一个字节的低 4 位作为偏移量
    offset = 0x0F & hmac_result[-1]

    # 按照 offset 从 HMAC 结果中提取 4 个字节，组合成一个整数
    # offset in [0, 15]，query range [0, 18], len(list)=20
    # 所以不会越界访问，也不会再用到最后一个字节
    code = (
        (hmac_result[offset] & 0x7F) << 24
        | (hmac_result[offset + 1] & 0xFF) << 16
        | (hmac_result[offset + 2] & 0xFF) << 8
        | (hmac_result[offset + 3] & 0xFF)
    )

    # 将生成的整数转换为字符串，补前导 0，反转
    password = f"{code:0{PASSWORD_MAIN_LENGTH}d}"[::-1]
    # 截取前 PASSWORD_MAIN_LENGTH-1 位，最后一位固定为 "0"
    return password[: PASSWORD_MAIN_LENGTH - 1] + "0"


def generate_totp(seed: int, duration: int, dt: datetime.datetime | None = None) -> str:
    """
    生成 TOTP 临时密码
    :param seed: 管理员种子密码整数
    :param duration: 密码有效时长（分钟）
    :param dt: 用于生成密码的时间，默认使用当前时间
    :return: 10 位临时密码字符串（前 8 位为动态密码，后 2 位为有效期分钟数）
    """
    if dt is None:
        dt = datetime.datetime.now()

    # 保持与原实现兼容，如果时间早于 2000 年 1 月 1 日，强制使用起点时间
    if dt.year < 2000:
        dt = EPOCH

    # 原逻辑 bug 导致多累加了当月完整天数 + 当天，这里补偿偏移保持完全等价
    month_days = calendar.monthrange(dt.year, dt.month)[1]
    total_seconds = int((dt - EPOCH).total_seconds()) + (month_days + 1) * 86400

    time_counter = total_seconds // (60 * duration)

    # 生成指定长度的密码主体
    password = generate_digit_password(seed, time_counter)
    # 追加有效期位数
    password += f"{duration:0{DURATION_LENGTH}d}"

    return password


def main():
    parser = argparse.ArgumentParser(
        description='生成与微信小程序"临时密码生成器"兼容的 TOTP 临时密码'
    )
    parser.add_argument("admin_password", type=int, help="管理员密码（仅数字）")
    parser.add_argument("duration", type=int, help="有效时长（分钟，范围 3-60）")

    args = parser.parse_args()

    # 验证有效时长范围
    if args.duration < 3 or args.duration > 60:
        print("错误：有效时长必须在 3 到 60 分钟之间", file=sys.stderr)
        sys.exit(1)

    seed = int(args.admin_password)
    password = generate_totp(seed, args.duration)

    print(password)


if __name__ == "__main__":
    main()
