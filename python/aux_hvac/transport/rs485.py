# -*- coding: utf-8 -*-
"""RS485 — заготовка под шинный интерфейс централизованного управления.

Статус: ЗАГОТОВКА. Транспортная часть рабочая, а вот параметры линии и формат
кадра для RS485-интерфейса AUX в этом репозитории ещё не описаны.

Что известно и что нет:

* физика — витая пара A/B, полудуплекс. Адаптер для программы прозрачен:
  направлением приём/передача чип управляет сам, поэтому RS485 ничем не
  отличается от обычного последовательного порта — пишем в порт и читаем
  из порта;
* скорость и формат — НЕ ПОДТВЕРЖДЕНЫ. Значения по умолчанию ниже взяты как
  самые ходовые для шин центрального управления HVAC и требуют проверки на
  реальном оборудовании;
* адресация и формат кадра — см. :mod:`aux_hvac.rs485_protocol`.

Порядок доработки, когда появится доступ к железу:

1. снять дамп шины скриптом ``aux_poll.py --rs485 --dump rs485.bin``
   и перебрать скорости из :data:`COMMON_BAUDRATES`;
2. по дампу определить стартовый байт/преамбулу и длину кадра;
3. заполнить :mod:`aux_hvac.rs485_protocol`.
"""

from __future__ import annotations

from .uart import SerialTransport

__all__ = ["RS485Transport", "COMMON_BAUDRATES"]

#: Скорости, которые имеет смысл перебирать при поиске параметров шины.
COMMON_BAUDRATES = (9600, 4800, 19200, 38400, 57600, 115200)

#: НЕ ПОДТВЕРЖДЕНО: предполагаемые параметры RS485-шины AUX.
RS485_BAUDRATE = 9600
RS485_PARITY = "N"
RS485_BYTESIZE = 8
RS485_STOPBITS = 1


class RS485Transport(SerialTransport):
    """Канал поверх RS485-адаптера.

    Адаптер прозрачен для программы: переключением приём/передача чип
    занимается сам. Поэтому класс отличается от
    :class:`~aux_hvac.transport.uart.SerialTransport` только параметрами
    линии по умолчанию и полем :attr:`address`.

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
        self.address = address

    def __repr__(self) -> str:  # pragma: no cover
        return "RS485Transport(%s, %d/%s%s%s, addr=0x%02X)" % (
            self.port,
            self.baudrate,
            self.bytesize,
            self.parity,
            self.stopbits,
            self.address,
        )
