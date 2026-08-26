# -*- coding: utf-8 -*-
"""Расчёт контрольной суммы пакетов AUX HVAC.

Алгоритм описан в README, раздел «Контрольная сумма»:

1. если длина данных нечётная, данные дополняются в конце нулевым байтом;
2. каждая пара байт трактуется как 16-битное little-endian число;
3. все 16-битные слова последовательно суммируются в 32-битном аккумуляторе;
4. старшие 16 бит суммы прибавляются к младшим (свёртка переноса);
5. результат побитово инвертируется.

В линию контрольная сумма уходит младшим байтом вперёд: CRC1 = low, CRC2 = high.

Алгоритм проверен на всех примерах пакетов из README (см. tests/test_protocol.py).
"""

from __future__ import annotations

__all__ = ["crc16", "crc16_bytes", "append_crc", "check_crc"]


def crc16(data: bytes) -> int:
    """Возвращает 16-битную контрольную сумму для ``data`` как целое число."""
    if len(data) % 2:
        data = bytes(data) + b"\x00"
    acc = 0
    for i in range(0, len(data), 2):
        acc += data[i] | (data[i + 1] << 8)
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def crc16_bytes(data: bytes) -> bytes:
    """Возвращает контрольную сумму в том виде, в каком она идёт в линию (LE)."""
    return crc16(data).to_bytes(2, "little")


def append_crc(data: bytes) -> bytes:
    """Дописывает контрольную сумму к данным (заголовок + тело)."""
    return bytes(data) + crc16_bytes(data)


def check_crc(frame: bytes) -> bool:
    """Проверяет целый кадр (заголовок + тело + 2 байта CRC)."""
    if len(frame) < 3:
        return False
    return crc16_bytes(frame[:-2]) == frame[-2:]
