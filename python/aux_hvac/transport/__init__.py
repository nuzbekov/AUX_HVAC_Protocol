# -*- coding: utf-8 -*-
"""Транспортный слой: UART, RS485, заглушка для тестов."""

from .base import LoopbackTransport, Transport, TransportError
from .uart import SerialTransport, list_ports
from .rs485 import RS485Transport

__all__ = [
    "Transport",
    "TransportError",
    "SerialTransport",
    "RS485Transport",
    "LoopbackTransport",
    "list_ports",
]
