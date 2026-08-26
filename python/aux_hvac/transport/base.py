# -*- coding: utf-8 -*-
"""Абстракция канала связи.

Кодек пакетов ничего не знает про физику линии. Всё, что ему нужно от
транспорта, — уметь открыться, отдать принятые байты и отправить свои.
Благодаря этому один и тот же :class:`~aux_hvac.packet.StreamDecoder`
работает и поверх UART wifi-модуля, и поверх RS485-шины, и поверх файла с
записанным логом.
"""

from __future__ import annotations

import abc
from typing import Optional

__all__ = ["Transport", "TransportError", "LoopbackTransport"]


class TransportError(IOError):
    """Ошибка канала: порт не открылся, оборвался, не отвечает."""


class Transport(abc.ABC):
    """Базовый интерфейс канала связи."""

    @abc.abstractmethod
    def open(self) -> None:
        """Открывает канал. Повторный вызов на открытом канале — no-op."""

    @abc.abstractmethod
    def close(self) -> None:
        """Закрывает канал."""

    @abc.abstractmethod
    def read(self, size: int = 256, timeout: Optional[float] = None) -> bytes:
        """Читает до ``size`` байт. Возвращает b'' по таймауту."""

    @abc.abstractmethod
    def write(self, data: bytes) -> int:
        """Отправляет байты, возвращает количество отправленных."""

    @property
    @abc.abstractmethod
    def is_open(self) -> bool:
        ...

    def reset_input(self) -> None:
        """Сбрасывает входной буфер. По умолчанию ничего не делает."""

    def __enter__(self) -> "Transport":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class LoopbackTransport(Transport):
    """Транспорт-заглушка для тестов и разбора записанных логов.

    Всё, что записано через :meth:`write`, складывается в :attr:`sent`.
    Всё, что подложено через :meth:`inject`, отдаётся из :meth:`read`.
    """

    def __init__(self, rx: bytes = b"") -> None:
        self._rx = bytearray(rx)
        self.sent = bytearray()
        self._open = False

    def open(self) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    @property
    def is_open(self) -> bool:
        return self._open

    def inject(self, data: bytes) -> None:
        """Подкладывает байты, как будто они пришли из линии."""
        self._rx.extend(data)

    def read(self, size: int = 256, timeout: Optional[float] = None) -> bytes:
        chunk = bytes(self._rx[:size])
        del self._rx[:size]
        return chunk

    def write(self, data: bytes) -> int:
        self.sent.extend(data)
        return len(data)

    def reset_input(self) -> None:
        self._rx.clear()
