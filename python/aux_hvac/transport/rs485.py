# -*- coding: utf-8 -*-
"""RS485 — заготовка под шинный интерфейс централизованного управления.

Статус: ЗАГОТОВКА. Транспортная часть рабочая (RS485 физически — это тот же
UART плюс управление направлением полудуплекса), а вот параметры линии и
формат кадра для RS485-интерфейса AUX в этом репозитории ещё не описаны.

Что известно и что нет:

* физика — витая пара A/B, полудуплекс; направление либо переключается
  автоматически самим адаптером (большинство USB-RS485 свистков), либо
  вручную сигналом DE/RE, который на дешёвых платах заведён на RTS;
* скорость и формат — НЕ ПОДТВЕРЖДЕНЫ. Значения по умолчанию ниже взяты
  как самые ходовые для шин центрального управления HVAC и требуют проверки
  на реальном оборудовании;
* адресация и формат кадра — см. :mod:`aux_hvac.rs485_protocol`.

Порядок доработки, когда появится доступ к железу:

1. снять дамп шины скриптом ``aux_poll.py --rs485 --sniff --raw``
   и перебрать скорости из :data:`COMMON_BAUDRATES`;
2. по дампу определить стартовый байт/преамбулу и длину кадра;
3. заполнить :mod:`aux_hvac.rs485_protocol`.
"""

from __future__ import annotations

from typing import Optional

from .uart import SerialTransport
from .base import TransportError

__all__ = ["RS485Transport", "COMMON_BAUDRATES"]

#: Скорости, которые имеет смысл перебирать при поиске параметров шины.
COMMON_BAUDRATES = (9600, 4800, 19200, 38400, 57600, 115200)

#: НЕ ПОДТВЕРЖДЕНО: предполагаемые параметры RS485-шины AUX.
RS485_BAUDRATE = 9600
RS485_PARITY = "N"
RS485_BYTESIZE = 8
RS485_STOPBITS = 1


class RS485Transport(SerialTransport):
    """Полудуплексный канал RS485.

    Отличается от :class:`~aux_hvac.transport.uart.SerialTransport` только
    управлением направлением передачи. Если адаптер переключает направление
    сам (типовой USB-RS485 на CH340/FT232 с автонаправлением), оставьте
    ``de_pin=None`` — тогда класс ведёт себя как обычный последовательный порт.

    :param de_pin: способ управления DE/RE:
        ``None`` — автоматическое переключение адаптером;
        ``"rts"`` — DE заведён на RTS;
        ``"dtr"`` — DE заведён на DTR;
        ``"native"`` — использовать режим RS485 драйвера pyserial.
    :param de_inverted: True, если активный уровень DE инвертирован.
    :param address: адрес устройства на шине. Пока не используется —
        задел под адресацию, см. :mod:`aux_hvac.rs485_protocol`.
    """

    def __init__(
        self,
        port: str,
        baudrate: int = RS485_BAUDRATE,
        parity: str = RS485_PARITY,
        bytesize: int = RS485_BYTESIZE,
        stopbits: int = RS485_STOPBITS,
        timeout: float = 0.2,
        de_pin: Optional[str] = None,
        de_inverted: bool = False,
        address: int = 0x01,
    ) -> None:
        super().__init__(
            port=port,
            baudrate=baudrate,
            parity=parity,
            bytesize=bytesize,
            stopbits=stopbits,
            timeout=timeout,
        )
        self.de_pin = de_pin
        self.de_inverted = de_inverted
        self.address = address

    # ------------------------------------------------------------ жизненный цикл

    def open(self) -> None:
        super().open()
        if self.de_pin == "native":
            self._enable_native_rs485()
        else:
            self._set_driver_enable(False)

    def _enable_native_rs485(self) -> None:
        """Включает аппаратный режим RS485 в драйвере pyserial.

        Поддерживается не всеми платформами и не всеми драйверами: на Windows
        для большинства USB-свистков это исключение, и тогда остаётся ручное
        управление через RTS/DTR либо автонаправление адаптера.
        """
        try:
            import serial.rs485

            settings = serial.rs485.RS485Settings(
                rts_level_for_tx=not self.de_inverted,
                rts_level_for_rx=self.de_inverted,
            )
            self._serial.rs485_mode = settings
        except Exception as exc:  # pragma: no cover - зависит от платформы
            raise TransportError(
                "драйвер не поддерживает аппаратный режим RS485: %s. "
                "Используйте de_pin='rts' или адаптер с автонаправлением." % exc
            ) from exc

    def _set_driver_enable(self, transmitting: bool) -> None:
        """Переводит трансивер в режим передачи или приёма."""
        if self._serial is None or self.de_pin in (None, "native"):
            return
        level = transmitting != self.de_inverted
        if self.de_pin == "rts":
            self._serial.rts = level
        elif self.de_pin == "dtr":
            self._serial.dtr = level
        else:
            raise TransportError("неизвестный способ управления DE: %r" % self.de_pin)

    # ------------------------------------------------------------ обмен

    def write(self, data: bytes) -> int:
        """Передаёт кадр, подняв DE на время передачи.

        ``flush()`` внутри :meth:`SerialTransport.write` дожидается ухода
        последнего байта, поэтому опускать DE сразу после него безопасно.
        """
        self._set_driver_enable(True)
        try:
            return super().write(data)
        finally:
            self._set_driver_enable(False)

    def __repr__(self) -> str:  # pragma: no cover
        return "RS485Transport(%s, %d/%s%s%s, DE=%s, addr=0x%02X)" % (
            self.port,
            self.baudrate,
            self.bytesize,
            self.parity,
            self.stopbits,
            self.de_pin or "auto",
            self.address,
        )
