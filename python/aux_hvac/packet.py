# -*- coding: utf-8 -*-
"""Кадровый уровень протокола: заголовок, тело, CRC.

Здесь нет никакой семантики полей тела — только разбор и сборка кадра.
Смысл байтов тела разбирается в :mod:`aux_hvac.state`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, List, Optional

from .const import (
    CRC_LEN,
    HEADER_LEN,
    MAX_PACKET_LEN,
    MIN_PACKET_LEN,
    START_BYTE,
    WIFI_FLAG_AC,
    WIFI_FLAG_MODULE,
    Command,
    PacketType,
)
from .crc import append_crc, crc16_bytes

__all__ = [
    "Packet",
    "PacketError",
    "StreamDecoder",
    "hexdump",
    "ping_request",
    "ping_response",
    "request_indoor",
    "request_outdoor",
    "control",
    "init_response",
    "unknown_0b",
]


class PacketError(ValueError):
    """Кадр не разобрался: битый CRC, неверный старт, недостаточная длина."""


def hexdump(data: bytes, sep: str = " ") -> str:
    """Байты в привычный по README вид: BB 00 01 00."""
    return sep.join("%02X" % b for b in data)


@dataclass
class Packet:
    """Один кадр протокола.

    Поля заголовка названы так же, как в README. Нерасшифрованные байты
    сохранены как есть, чтобы кадр можно было пересобрать байт в байт.
    """

    ptype: int
    """Байт 2 (TYPE)."""

    wifi: int = WIFI_FLAG_MODULE
    """Байт 3: 0x80 — пакет модуля, 0x00 — пакет кондиционера."""

    body: bytes = b""
    """Тело пакета, байты 8..(8+LEN-1)."""

    unknown1: int = 0x00
    """Байт 1, назначение неизвестно, во всех логах 0x00."""

    unknown4: int = 0x00
    """Байт 4: 0x01 у исходящих PING/INIT, иначе 0x00."""

    unknown5: int = 0x00
    """Байт 5, назначение неизвестно, во всех логах 0x00."""

    unknown7: int = 0x00
    """Байт 7, назначение неизвестно, во всех логах 0x00."""

    crc_ok: bool = True
    """False, если кадр принят с ошибкой контрольной суммы."""

    truncated: bool = False
    """True для битых пакетов с потерянным старшим байтом CRC (README, TYPE=0x01)."""

    raw: bytes = field(default=b"", repr=False)
    """Байты, реально принятые из линии (для логирования)."""

    # ------------------------------------------------------------------ свойства

    @property
    def from_module(self) -> bool:
        """Кадр отправлен wifi-модулем (направление [=>])."""
        return self.wifi == WIFI_FLAG_MODULE

    @property
    def from_ac(self) -> bool:
        """Кадр отправлен кондиционером (направление [<=])."""
        return self.wifi == WIFI_FLAG_AC

    @property
    def direction(self) -> str:
        return "[=>]" if self.from_module else "[<=]"

    @property
    def cmd(self) -> Optional[int]:
        """CMD пакета.

        Для TYPE=0x06 команда лежит в байте 8 (первый байт тела),
        для TYPE=0x07 — в байте 9 (второй байт тела). Для остальных типов
        понятия CMD нет.
        """
        if self.ptype == PacketType.CMD and len(self.body) >= 1:
            return self.body[0]
        if self.ptype == PacketType.INFO and len(self.body) >= 2:
            return self.body[1]
        return None

    @property
    def header(self) -> bytes:
        return bytes(
            (
                START_BYTE,
                self.unknown1,
                self.ptype,
                self.wifi,
                self.unknown4,
                self.unknown5,
                len(self.body),
                self.unknown7,
            )
        )

    @property
    def crc(self) -> bytes:
        """Корректная контрольная сумма кадра, младший байт первым."""
        return crc16_bytes(self.header + self.body)

    # ------------------------------------------------------------------ кодек

    def encode(self) -> bytes:
        """Собирает кадр целиком: заголовок + тело + CRC."""
        if not 0 <= len(self.body) <= 0xFF:
            raise PacketError("длина тела %d вне допустимого диапазона" % len(self.body))
        return append_crc(self.header + self.body)

    @classmethod
    def decode(cls, frame: bytes, strict: bool = True) -> "Packet":
        """Разбирает кадр целиком.

        :param frame: заголовок + тело + 2 байта CRC.
        :param strict: если True, при неверной CRC бросается :class:`PacketError`,
            иначе кадр возвращается с ``crc_ok=False``.
        """
        frame = bytes(frame)
        if len(frame) < MIN_PACKET_LEN:
            raise PacketError("кадр короче %d байт: %s" % (MIN_PACKET_LEN, hexdump(frame)))
        if frame[0] != START_BYTE:
            raise PacketError("нет стартового байта 0x%02X: %s" % (START_BYTE, hexdump(frame)))

        body_len = frame[6]
        expected = HEADER_LEN + body_len + CRC_LEN
        if len(frame) != expected:
            raise PacketError(
                "LEN=%d требует кадр в %d байт, получено %d" % (body_len, expected, len(frame))
            )

        computed = crc16_bytes(frame[:-CRC_LEN])
        crc_ok = computed == frame[-CRC_LEN:]
        if strict and not crc_ok:
            raise PacketError(
                "неверная CRC: в кадре %s, посчитано %s"
                % (hexdump(frame[-CRC_LEN:]), hexdump(computed))
            )

        return cls(
            ptype=frame[2],
            wifi=frame[3],
            body=frame[HEADER_LEN:HEADER_LEN + body_len],
            unknown1=frame[1],
            unknown4=frame[4],
            unknown5=frame[5],
            unknown7=frame[7],
            crc_ok=crc_ok,
            raw=frame,
        )

    # ------------------------------------------------------------------ вывод

    def describe(self) -> str:
        """Однострочное описание кадра в стиле логов из README."""
        try:
            tname = PacketType(self.ptype).name
        except ValueError:
            tname = "TYPE_%02X" % self.ptype

        cname = ""
        cmd = self.cmd
        if cmd is not None:
            try:
                cname = " CMD=%s" % Command(cmd).name
            except ValueError:
                cname = " CMD=0x%02X" % cmd

        flags = ""
        if not self.crc_ok:
            flags += " !CRC"
        if self.truncated:
            flags += " !TRUNC"

        raw = self.raw or self.encode()
        return "%s %s%s [%s] %s%s" % (
            self.direction,
            tname,
            cname,
            hexdump(raw[:HEADER_LEN]),
            hexdump(raw[HEADER_LEN:]),
            flags,
        )

    def __str__(self) -> str:  # pragma: no cover - удобство отладки
        return self.describe()


class StreamDecoder:
    """Потоковый разборщик байтов из последовательного порта.

    Умеет то, чего требует реальная линия:

    * пересинхронизация по стартовому байту 0xBB после мусора;
    * лишний нулевой байт в теле у Royal Clima (кадр на 35 байт);
    * битые пакеты, у которых потерян старший байт CRC (README, TYPE=0x01).

    Использование::

        dec = StreamDecoder()
        for packet in dec.feed(port.read(64)):
            print(packet.describe())
    """

    def __init__(self, keep_bad_crc: bool = True, max_buffer: int = 4096) -> None:
        self.keep_bad_crc = keep_bad_crc
        """Отдавать ли наверх кадры с неверной CRC (с ``crc_ok=False``)."""
        self._buf = bytearray()
        self._max_buffer = max_buffer
        self.dropped_bytes = 0
        """Счётчик выброшенных при пересинхронизации байтов."""

    def reset(self) -> None:
        self._buf.clear()

    def feed(self, data: bytes) -> List[Packet]:
        """Скармливает очередную порцию байтов, возвращает готовые кадры."""
        self._buf.extend(data)
        if len(self._buf) > self._max_buffer:
            # линия сошла с ума — выкидываем всё, кроме хвоста
            extra = len(self._buf) - self._max_buffer
            self.dropped_bytes += extra
            del self._buf[:extra]
        return list(self._drain())

    def _drain(self) -> Iterator[Packet]:
        while True:
            packet = self._try_one()
            if packet is None:
                return
            yield packet

    def _try_one(self) -> Optional[Packet]:
        buf = self._buf

        # 1. пересинхронизация по стартовому байту
        start = buf.find(START_BYTE)
        if start == -1:
            self.dropped_bytes += len(buf)
            buf.clear()
            return None
        if start > 0:
            self.dropped_bytes += start
            del buf[:start]

        if len(buf) < MIN_PACKET_LEN:
            return None

        body_len = buf[6]
        total = HEADER_LEN + body_len + CRC_LEN
        if total > MAX_PACKET_LEN + 1:
            # заведомо мусорный LEN — сдвигаемся на байт и пробуем снова
            return self._resync()

        # 2. штатный кадр
        if len(buf) >= total:
            frame = bytes(buf[:total])
            if crc16_bytes(frame[:-CRC_LEN]) == frame[-CRC_LEN:]:
                del buf[:total]
                return Packet.decode(frame)

        # 3. Royal Clima: в конец тела добавлен лишний нулевой байт,
        #    но поле LEN его не учитывает.
        if len(buf) >= total + 1:
            frame = bytes(buf[:total + 1])
            if crc16_bytes(frame[:-CRC_LEN]) == frame[-CRC_LEN:]:
                del buf[:total + 1]
                packet = Packet(
                    ptype=frame[2],
                    wifi=frame[3],
                    body=frame[HEADER_LEN:-CRC_LEN],
                    unknown1=frame[1],
                    unknown4=frame[4],
                    unknown5=frame[5],
                    unknown7=frame[7],
                    raw=frame,
                )
                return packet

        # 4. битый пакет: старший байт CRC потерялся, сразу за младшим
        #    начинается следующий кадр.
        if len(buf) >= total:
            frame = bytes(buf[:total - 1])
            good = crc16_bytes(frame[:-1])
            if good[0] == frame[-1] and buf[total - 1] == START_BYTE:
                del buf[:total - 1]
                packet = Packet.decode(frame[:-1] + good, strict=False)
                packet.truncated = True
                packet.crc_ok = False
                packet.raw = frame
                if not self.keep_bad_crc:
                    return self._try_one()
                return packet

        if len(buf) < total + 1:
            return None  # ждём ещё байтов

        # 5. ничего не сошлось — это мусор
        return self._resync()

    def _resync(self) -> Optional[Packet]:
        """Сдвигает буфер на один байт и повторяет попытку разбора."""
        self.dropped_bytes += 1
        del self._buf[:1]
        return self._try_one()


# --------------------------------------------------------------------------
# Готовые конструкторы известных пакетов
# --------------------------------------------------------------------------

def ping_response() -> Packet:
    """Ответ wifi-модуля на дежурный ping кондиционера (README, TYPE=0x01)."""
    return Packet(
        ptype=PacketType.PING,
        wifi=WIFI_FLAG_MODULE,
        unknown4=0x01,
        body=bytes((0x1C, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)),
    )


def ping_request() -> Packet:
    """Дежурный ping кондиционера. Модулю не нужен, полезен для эмуляции сплита."""
    return Packet(ptype=PacketType.PING, wifi=WIFI_FLAG_AC)


def request_indoor(seq: int = 0x01) -> Packet:
    """Запрос статуса внутреннего блока (TYPE=0x06, CMD=0x11)."""
    return Packet(ptype=PacketType.CMD, body=bytes((Command.INDOOR, seq)))


def request_outdoor(seq: int = 0x01) -> Packet:
    """Запрос статуса внешнего блока (TYPE=0x06, CMD=0x21)."""
    return Packet(ptype=PacketType.CMD, body=bytes((Command.OUTDOOR, seq)))


def control(body13: bytes, seq: int = 0x01) -> Packet:
    """Команда управления (TYPE=0x06, CMD=0x01).

    :param body13: 13 байт, идентичных байтам 10..22 пакета TYPE=0x07 CMD=0x11.
    """
    body13 = bytes(body13)
    if len(body13) != 13:
        raise PacketError(
            "тело команды управления должно быть 13 байт, получено %d" % len(body13)
        )
    return Packet(ptype=PacketType.CMD, body=bytes((Command.CONTROL, seq)) + body13)


def init_response() -> Packet:
    """Ответ модуля на пакет инициирования (TYPE=0x09)."""
    return Packet(ptype=PacketType.INIT, wifi=WIFI_FLAG_MODULE, unknown4=0x01)


def unknown_0b(counter: int = 0x01) -> Packet:
    """Пакет TYPE=0x0B. Назначение неизвестно, кондиционер его игнорирует."""
    return Packet(ptype=PacketType.UNKNOWN_0B, body=bytes((counter & 0xFF, 0x00)))
