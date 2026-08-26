# -*- coding: utf-8 -*-
"""UART поверх COM-порта — штатный канал wifi-модуля.

Параметры линии из README: 4800 бод, 8 бит данных, чётность even, 1 стоп-бит.
"""

from __future__ import annotations

from typing import List, Optional

from ..const import UART_BAUDRATE, UART_BYTESIZE, UART_PARITY, UART_STOPBITS
from .base import Transport, TransportError

__all__ = ["SerialTransport", "list_ports"]


def _require_serial():
    try:
        import serial  # noqa: F401
    except ImportError as exc:  # pragma: no cover - зависит от окружения
        raise TransportError(
            "не установлен пакет pyserial. Установите: pip install pyserial"
        ) from exc
    return serial


def list_ports() -> List[str]:
    """Возвращает список доступных последовательных портов в виде строк."""
    serial = _require_serial()
    from serial.tools import list_ports as lp

    return ["%s — %s" % (p.device, p.description) for p in lp.comports()]


class SerialTransport(Transport):
    """Канал поверх последовательного порта (COM/ttyUSB).

    :param port: имя порта, например ``COM6`` или ``/dev/ttyUSB0``.
    :param baudrate: по умолчанию 4800 — как требует протокол AUX.
    :param parity: по умолчанию ``E`` (even).
    :param timeout: таймаут чтения в секундах.
    """

    def __init__(
        self,
        port: str,
        baudrate: int = UART_BAUDRATE,
        parity: str = UART_PARITY,
        bytesize: int = UART_BYTESIZE,
        stopbits: int = UART_STOPBITS,
        timeout: float = 0.2,
    ) -> None:
        self.port = port
        self.baudrate = baudrate
        self.parity = parity
        self.bytesize = bytesize
        self.stopbits = stopbits
        self.timeout = timeout
        self._serial = None

    # ------------------------------------------------------------ жизненный цикл

    def open(self) -> None:
        if self._serial is not None and self._serial.is_open:
            return
        serial = _require_serial()
        try:
            self._serial = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=self.bytesize,
                parity=self.parity,
                stopbits=self.stopbits,
                timeout=self.timeout,
            )
        except Exception as exc:
            raise TransportError("не удалось открыть порт %s: %s" % (self.port, exc)) from exc

    def close(self) -> None:
        if self._serial is not None:
            try:
                self._serial.close()
            finally:
                self._serial = None

    @property
    def is_open(self) -> bool:
        return self._serial is not None and self._serial.is_open

    # ------------------------------------------------------------ обмен

    def read(self, size: int = 256, timeout: Optional[float] = None) -> bytes:
        if self._serial is None:
            raise TransportError("порт %s не открыт" % self.port)
        if timeout is not None and timeout != self._serial.timeout:
            self._serial.timeout = timeout
        waiting = self._serial.in_waiting
        # если в буфере уже что-то есть, забираем без ожидания таймаута
        return self._serial.read(min(size, waiting) if waiting else 1)

    def write(self, data: bytes) -> int:
        if self._serial is None:
            raise TransportError("порт %s не открыт" % self.port)
        written = self._serial.write(data)
        self._serial.flush()
        return written

    def reset_input(self) -> None:
        if self._serial is not None:
            self._serial.reset_input_buffer()

    def __repr__(self) -> str:  # pragma: no cover
        return "SerialTransport(%s, %d/%s%s%s)" % (
            self.port,
            self.baudrate,
            self.bytesize,
            self.parity,
            self.stopbits,
        )
