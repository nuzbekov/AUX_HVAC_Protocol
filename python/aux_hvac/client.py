# -*- coding: utf-8 -*-
"""Высокоуровневый клиент: опрос кондиционера поверх любого транспорта.

Клиент умеет два режима работы:

* **пассивный (sniffer)** — только слушает линию между штатным wifi-модулем и
  сплитом и разбирает всё, что видит. Ничего не передаёт, поэтому безопасен.
* **активный (poller)** — сам изображает wifi-модуль: отвечает на ping-пакеты
  и периодически запрашивает статус внутреннего и внешнего блоков.

ВАЖНО: активный режим нельзя включать, если к линии уже подключён штатный
wifi-модуль — два «модуля» на одной линии начнут перебивать друг друга.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .const import Command, PacketType
from .packet import (
    Packet,
    StreamDecoder,
    init_response,
    ping_response,
    request_indoor,
    request_outdoor,
)
from .state import IndoorState, OutdoorState, decode_state
from .transport.base import Transport

__all__ = ["AuxClient", "ClientStats"]

logger = logging.getLogger("aux_hvac.client")


@dataclass
class ClientStats:
    """Счётчики для диагностики линии."""

    packets: int = 0
    sent: int = 0
    bad_crc: int = 0
    undecodable: int = 0
    truncated: int = 0
    dropped_bytes: int = 0
    pings_answered: int = 0
    by_type: dict = field(default_factory=dict)

    def note(self, packet: Packet) -> None:
        self.packets += 1
        if not packet.crc_ok:
            self.bad_crc += 1
        if packet.truncated:
            self.truncated += 1
        key = "0x%02X" % packet.ptype
        self.by_type[key] = self.by_type.get(key, 0) + 1

    def describe_lines(self):
        """Счётчики двумя строками: принятое и всё остальное.

        Одной строкой они не влезают в панель монитора: панель обрезает
        содержимое по ширине окна, и хвост со счётчиком отправленного и
        разбивкой по типам пропадал. Вторая строка начинается с мусорных байт.
        """
        # без не-ASCII: сводку печатают и из чужих скриптов на консоли cp1251
        types = ", ".join("%s x%d" % (k, v) for k, v in sorted(self.by_type.items()))
        return [
            "принято пакетов: %d (битых CRC: %d, обрезанных: %d, "
            "с неразобранным телом: %d)"
            % (self.packets, self.bad_crc, self.truncated, self.undecodable),
            "мусорных байт: %d, отправлено: %d (ping: %d); типы: %s"
            % (self.dropped_bytes, self.sent, self.pings_answered, types or "нет"),
        ]

    def describe(self) -> str:
        """Те же счётчики одной строкой — для итоговой сводки при выходе."""
        return ", ".join(self.describe_lines())


class AuxClient:
    """Клиент протокола AUX поверх произвольного транспорта.

    :param transport: канал связи (:class:`~aux_hvac.transport.base.Transport`).
    :param active: изображать wifi-модуль (отвечать на ping, слать запросы).
    :param poll_interval: период запроса статусов в активном режиме, секунды.
    :param answer_ping: отвечать ли на дежурные пакеты кондиционера.
    :param on_packet: колбэк на каждый принятый кадр.
    :param on_state: колбэк на каждое разобранное состояние блока.
    :param on_send: колбэк на каждый отправленный кадр.
    """

    def __init__(
        self,
        transport: Transport,
        active: bool = False,
        poll_interval: float = 10.0,
        answer_ping: bool = True,
        on_packet: Optional[Callable[[Packet], None]] = None,
        on_state: Optional[Callable[[object, Packet], None]] = None,
        on_send: Optional[Callable[[Packet], None]] = None,
    ) -> None:
        self.transport = transport
        self.active = active
        self.poll_interval = poll_interval
        self.answer_ping = answer_ping
        self.on_packet = on_packet
        self.on_state = on_state
        self.on_send = on_send

        self.decoder = StreamDecoder()
        self.stats = ClientStats()

        self.indoor: Optional[IndoorState] = None
        """Последний известный статус внутреннего блока."""

        self.outdoor: Optional[OutdoorState] = None
        """Последний известный статус внешнего блока."""

        self._last_poll = 0.0
        self._poll_toggle = False

    # ------------------------------------------------------------ жизненный цикл

    def open(self) -> "AuxClient":
        self.transport.open()
        return self

    def close(self) -> None:
        self.transport.close()

    def __enter__(self) -> "AuxClient":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------ обмен

    def send(self, packet: Packet) -> None:
        """Отправляет кадр в линию."""
        raw = packet.encode()
        logger.debug("TX %s", packet.describe())
        self.transport.write(raw)
        self.stats.sent += 1
        if self.on_send is not None:
            self.on_send(packet)

    def poll_once(self, read_size: int = 256) -> List[Packet]:
        """Один шаг цикла: прочитать линию, разобрать, при нужде ответить.

        Возвращает список кадров, разобранных за этот шаг.
        """
        chunk = self.transport.read(read_size)
        packets = self.decoder.feed(chunk) if chunk else []
        self.stats.dropped_bytes = self.decoder.dropped_bytes

        for packet in packets:
            self._handle(packet)

        if self.active:
            self._maybe_request()

        return packets

    def run(self, duration: Optional[float] = None, idle_sleep: float = 0.02) -> None:
        """Крутит цикл опроса.

        :param duration: сколько секунд работать; None — бесконечно.
        :param idle_sleep: пауза, когда в линии тихо, чтобы не жечь процессор.
        """
        deadline = None if duration is None else time.monotonic() + duration
        while deadline is None or time.monotonic() < deadline:
            if not self.poll_once():
                time.sleep(idle_sleep)

    # ------------------------------------------------------------ внутреннее

    def _handle(self, packet: Packet) -> None:
        self.stats.note(packet)
        logger.debug("RX %s", packet.describe())

        if self.on_packet is not None:
            self.on_packet(packet)

        state = None
        if packet.crc_ok:
            try:
                state = decode_state(packet)
            except ValueError as exc:
                # CRC сошлась, значит кадр принят верно, а вот его тело не
                # укладывается в описанный формат. Такое ждём на технике,
                # отличной от сплит-систем, поэтому кадр показываем целиком.
                self.stats.undecodable += 1
                logger.warning("тело пакета не разобрано (%s): %s", exc, packet.describe())

        if isinstance(state, IndoorState):
            self.indoor = state
        elif isinstance(state, OutdoorState):
            self.outdoor = state

        if state is not None and self.on_state is not None:
            self.on_state(state, packet)

        # автоответы имитируют поведение штатного wifi-модуля
        if not self.active or not packet.from_ac:
            return
        if packet.ptype == PacketType.PING and self.answer_ping:
            self.send(ping_response())
            self.stats.pings_answered += 1
        elif packet.ptype == PacketType.INIT:
            self.send(init_response())

    def _maybe_request(self) -> None:
        """Раз в :attr:`poll_interval` запрашивает статус, чередуя блоки."""
        now = time.monotonic()
        if now - self._last_poll < self.poll_interval:
            return
        self._last_poll = now
        self._poll_toggle = not self._poll_toggle
        self.send(request_indoor() if self._poll_toggle else request_outdoor())

    # ------------------------------------------------------------ команды

    def request(self, what: Command = Command.INDOOR) -> None:
        """Явно запрашивает статус внутреннего или внешнего блока."""
        if what == Command.INDOOR:
            self.send(request_indoor())
        elif what == Command.OUTDOOR:
            self.send(request_outdoor())
        else:
            raise ValueError("запросить можно только INDOOR или OUTDOOR, получено %r" % what)

    def apply(self, state: IndoorState) -> None:
        """Отправляет команду управления, собранную из статуса внутреннего блока.

        Штатная последовательность (README, «Последовательности команд»):
        запросить статус (CMD=0x11), поправить нужные биты, отправить командой
        CMD=0x01, дождаться подтверждения CMD=0x01 и перезапросить статус.
        """
        self.send(state.to_command())
