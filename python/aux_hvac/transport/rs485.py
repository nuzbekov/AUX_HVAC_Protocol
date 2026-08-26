# -*- coding: utf-8 -*-
"""RS485 — шинный интерфейс централизованного управления.

Что известно:

* физика — витая пара A/B, полудуплекс. Адаптер для программы прозрачен:
  направлением приём/передача чип управляет сам, поэтому RS485 ничем не
  отличается от обычного последовательного порта — пишем в порт и читаем
  из порта;
* **параметры линии — 9600/8-N-1, подтверждено** на шине контроллера
  фанкойла AUX: на этой скорости все кадры дампа сошлись по CRC. Обратите
  внимание, что это не те параметры, что у интерфейса wifi-модуля
  (4800/8-E-1), — интерфейсы разные во всём;
* формат кадра и адресация — расшифрованы, см.
  :mod:`aux_hvac.rs485_protocol`. Смысл регистров пока нет.

Если на другой модели в линии тишина, скорости для перебора собраны в
:data:`COMMON_BAUDRATES`, а снять дамп можно так::

    python aux_poll.py -p COM9 --rs485 --dump rs485.bin
    python aux_tool.py rs485 rs485.bin
"""

from __future__ import annotations

from .uart import SerialTransport

__all__ = ["RS485Transport", "COMMON_BAUDRATES"]

#: Скорости, которые имеет смысл перебирать при поиске параметров шины.
COMMON_BAUDRATES = (9600, 4800, 19200, 38400, 57600, 115200)

#: Параметры RS485-шины AUX. Подтверждены дампом шины контроллера фанкойла.
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

    :param address: адрес устройства на шине. Транспортом не используется:
        адреса лежат в самом кадре, см. :mod:`aux_hvac.rs485_protocol`. Поле
        оставлено, чтобы задать свой адрес, когда появится передача.
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
