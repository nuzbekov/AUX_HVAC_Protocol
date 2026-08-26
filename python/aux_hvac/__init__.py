# -*- coding: utf-8 -*-
"""Кодек UART-протокола кондиционеров на базе AUX.

Реализация ровно по README этого репозитория. Ничего сверх описанного здесь
не додумано: там, где протокол не расшифрован, байты отдаются сырыми, а
гипотезы помечены в docstring'ах.

Быстрый старт — пассивное прослушивание линии::

    from aux_hvac import AuxClient, SerialTransport

    with AuxClient(SerialTransport("COM5")) as client:
        client.on_packet = lambda p: print(p.describe())
        client.run(duration=60)

Разбор отдельного кадра::

    from aux_hvac import Packet, decode_state

    packet = Packet.decode(bytes.fromhex("bb000700000018000121c03d000254..."))
    print(decode_state(packet).describe())
"""

from __future__ import annotations

from .const import (
    Command,
    FanSpeed,
    HorizontalLouver,
    Mode,
    PacketType,
    RealFanSpeed,
    VerticalLouver,
)
from .crc import append_crc, check_crc, crc16, crc16_bytes
from .packet import (
    Packet,
    PacketError,
    StreamDecoder,
    control,
    hexdump,
    init_response,
    ping_request,
    ping_response,
    request_indoor,
    request_outdoor,
    unknown_0b,
)
from .state import IndoorState, OutdoorState, decode_state
from .client import AuxClient, ClientStats
from .transport.base import LoopbackTransport, Transport, TransportError
from .transport.uart import SerialTransport, list_ports
from .transport.rs485 import RS485Transport

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # кадры
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
    # CRC
    "crc16",
    "crc16_bytes",
    "append_crc",
    "check_crc",
    # состояния
    "IndoorState",
    "OutdoorState",
    "decode_state",
    # перечисления
    "PacketType",
    "Command",
    "Mode",
    "FanSpeed",
    "RealFanSpeed",
    "VerticalLouver",
    "HorizontalLouver",
    # транспорт
    "Transport",
    "TransportError",
    "SerialTransport",
    "RS485Transport",
    "LoopbackTransport",
    "list_ports",
    # клиент
    "AuxClient",
    "ClientStats",
]
