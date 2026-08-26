#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Опрос кондиционера AUX через COM-порт.

Два режима работы:

**Пассивный (по умолчанию).** Скрипт молча слушает линию между штатным
wifi-модулем и сплитом и разбирает всё, что видит. Ничего не передаёт,
поэтому безопасен и не мешает работе штатного модуля.

**Активный (``--active``).** Скрипт сам изображает wifi-модуль: отвечает на
дежурные ping-пакеты и раз в ``--interval`` секунд запрашивает статус
внутреннего и внешнего блоков.

    ВНИМАНИЕ: активный режим нельзя включать, если к линии уже подключён
    штатный wifi-модуль. Два «модуля» на одной линии будут перебивать
    друг друга.

Примеры::

    python aux_poll.py --list                      список портов
    python aux_poll.py -p COM6 --loopback          проверка адаптера (перемычка TX-RX)
    python aux_poll.py -p COM6                     пассивное прослушивание
    python aux_poll.py -p COM6 --active            активный опрос
    python aux_poll.py -p COM6 --json --log ac.jsonl
    python aux_poll.py -p COM6 --dump line.bin     сохранить сырой поток
    python aux_poll.py -p COM6 --send "BB 00 06 80 00 00 02 00 11 01 2B 7E"
    python aux_poll.py -p COM6 --rs485 --dump rs485.bin  заготовка: дамп RS485-шины

Сырой дамп потом разбирается офлайн::

    python aux_tool.py replay line.bin --binary
"""

from __future__ import annotations

import argparse
import binascii
import json
import re
import signal
import sys
import time
from collections import deque
from typing import Optional

sys.path.insert(0, __file__.rsplit("aux_poll.py", 1)[0] or ".")

# Консоль Windows по умолчанию не в UTF-8, а весь вывод здесь русскоязычный.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):  # pragma: no cover - старый Python или не-TTY
        pass

from aux_hvac import (  # noqa: E402
    AuxClient,
    IndoorState,
    OutdoorState,
    Packet,
    RS485Transport,
    SerialTransport,
    StreamDecoder,
    TransportError,
    hexdump,
    list_ports,
    request_indoor,
)
from aux_hvac.const import UART_BAUDRATE, UART_PARITY  # noqa: E402

_stop = False


def _install_sigint() -> None:
    """Ctrl+C должен дать скрипту закрыть порт и напечатать сводку."""

    def handler(signum, frame):  # pragma: no cover - интерактивное поведение
        global _stop
        _stop = True
        print("\nОстановка...", file=sys.stderr)

    signal.signal(signal.SIGINT, handler)


def _parse_hex(text: str) -> bytes:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", re.sub(r"0[xX]", "", text))
    if len(cleaned) % 2:
        raise ValueError("нечётное количество hex-символов: %r" % text)
    return binascii.unhexlify(cleaned)


# ===========================================================================
#  Вывод
# ===========================================================================

class Reporter:
    """Печатает разобранные кадры и пишет их в файл."""

    #: Сколько секунд кадр считается кандидатом в эхо после отправки.
    ECHO_WINDOW = 2.0

    def __init__(self, args) -> None:
        self.args = args
        self.log = open(args.log, "a", encoding="utf-8") if args.log else None
        self.dump = open(args.dump, "ab") if args.dump else None
        self.started = time.time()
        self._sent = deque(maxlen=16)
        """Недавно отправленные кадры: (байты, момент отправки)."""
        self._echo_noted = False

    def close(self) -> None:
        for fh in (self.log, self.dump):
            if fh is not None:
                fh.close()

    def _emit(self, line: str) -> None:
        print(line, flush=True)
        if self.log is not None:
            self.log.write(line + "\n")
            self.log.flush()

    def _is_echo(self, packet: Packet) -> bool:
        """Кадр — это вернувшаяся собственная передача?

        Отличить эхо по содержимому нельзя: байт 3 говорит лишь о том, кто
        кадр составил, и при пассивном прослушивании кадры wifi-модуля
        принимать совершенно нормально. Поэтому сверяемся с тем, что сами
        только что отправили.
        """
        raw = packet.raw or packet.encode()
        now = time.monotonic()
        return any(
            sent == raw and now - ts < self.ECHO_WINDOW for sent, ts in self._sent
        )

    def on_packet(self, packet: Packet) -> None:
        if self.args.json:
            return  # в JSON-режиме печатаем на уровне состояния, а не кадра
        stamp = time.strftime("%H:%M:%S")
        echo = self._is_echo(packet)
        self._emit("%s %s%s" % (stamp, packet.describe(), "  <- эхо" if echo else ""))
        if echo and not self._echo_noted:
            self._echo_noted = True
            print(
                "Вернулась собственная передача: TX замкнут на RX. Адаптер и "
                "настройки порта исправны;\nдля работы с кондиционером снимите "
                "перемычку.",
                file=sys.stderr,
            )

    def on_send(self, packet: Packet) -> None:
        """Отправленные кадры видно наравне с принятыми.

        Без этого активный режим выглядит молчащим до первого ответа
        кондиционера, и непонятно, ушёл запрос в линию или нет.
        """
        self._sent.append((packet.encode(), time.monotonic()))
        if self.args.json:
            return
        self._emit("%s %s" % (time.strftime("%H:%M:%S"), packet.describe()))

    def on_state(self, state, packet: Packet) -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        if self.args.json:
            record = {
                "ts": stamp,
                "kind": "indoor" if isinstance(state, IndoorState) else "outdoor",
                "cmd": "0x%02X" % (packet.cmd or 0),
                "raw": hexdump(packet.raw or packet.encode()),
            }
            record.update(state.to_dict())
            self._emit(json.dumps(record, ensure_ascii=False))
        else:
            self._emit("         %s" % state.describe())


_SILENCE_HINT = (
    "Проверьте: тот ли порт (--list), не перепутаны ли TX и RX, "
    "общая ли земля, подано ли питание на кондиционер, "
    "верны ли скорость и чётность (протокол требует 4800/8-E-1)."
)

#: Через сколько секунд тишины в линии предупредить пользователя.
_SILENCE_TIMEOUT = 15.0


def _warn_if_silent(rx: dict, args) -> None:
    """Печатает подсказку, если из линии давно ничего не приходило.

    Без неё скрипт на неверном порту или неверной распайке выглядит просто
    зависшим: он честно передаёт запросы, но ответов нет, и сказать об этом
    некому.
    """
    now = time.monotonic()
    if now - rx["last"] < _SILENCE_TIMEOUT or now - rx["warned"] < _SILENCE_TIMEOUT:
        return
    rx["warned"] = now
    if rx["bytes"]:
        print(
            "В линии тишина уже %.0f с (всего принято %d байт)."
            % (now - rx["last"], rx["bytes"]),
            file=sys.stderr,
        )
    else:
        print(
            "Из линии не пришло ни одного байта за %.0f с. %s"
            % (now - rx["last"], _SILENCE_HINT),
            file=sys.stderr,
        )


# ===========================================================================
#  Режимы
# ===========================================================================

def run_aux(args) -> int:
    """Штатный режим: UART-протокол wifi-модуля."""
    transport = SerialTransport(
        port=args.port,
        baudrate=args.baud,
        parity=args.parity,
        timeout=args.read_timeout,
    )
    reporter = Reporter(args)

    def on_raw_chunk(chunk: bytes) -> None:
        if reporter.dump is not None and chunk:
            reporter.dump.write(chunk)

    client = AuxClient(
        transport=transport,
        active=args.active,
        poll_interval=args.interval,
        answer_ping=not args.no_ping,
        on_packet=reporter.on_packet,
        on_state=reporter.on_state,
        on_send=reporter.on_send,
    )

    # порт открываем до баннера, иначе сообщение об ошибке теряется в выводе
    try:
        client.open()
    except TransportError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        print("Список доступных портов: python aux_poll.py --list", file=sys.stderr)
        reporter.close()
        return 2

    print("Порт %s: %d бод, %s, 8 бит, 1 стоп-бит." % (args.port, args.baud, args.parity))
    print("Режим: %s." % ("АКТИВНЫЙ (эмуляция wifi-модуля)" if args.active else "пассивный"))
    if args.active:
        print("Отключите штатный wifi-модуль от линии, иначе будут коллизии.")
        print(
            "Запрос статуса раз в %g с. Строки [=>] — что ушло в линию, "
            "[<=] — что пришло." % args.interval
        )
    else:
        print("Скрипт только слушает и ничего не передаёт. Если штатного "
              "wifi-модуля на линии нет,")
        print("кондиционер сам шлёт только ping раз в ~3 с — для запроса "
              "статуса нужен --active.")
    print("Ctrl+C — остановка.\n")

    # перехватываем сырые байты: для --dump и для контроля тишины в линии
    original_read = transport.read
    rx = {"bytes": 0, "last": time.monotonic(), "warned": 0.0}

    def read_tracked(size=256, timeout=None):
        chunk = original_read(size, timeout)
        if chunk:
            rx["bytes"] += len(chunk)
            rx["last"] = time.monotonic()
            on_raw_chunk(chunk)
        return chunk

    transport.read = read_tracked  # type: ignore[assignment]

    try:
        if args.send:
            frame = _parse_hex(args.send)
            print("Отправка: %s" % hexdump(frame))
            transport.write(frame)

        deadline = None if args.duration is None else time.monotonic() + args.duration
        while not _stop and (deadline is None or time.monotonic() < deadline):
            if not client.poll_once():
                time.sleep(0.02)
            _warn_if_silent(rx, args)
    except TransportError as exc:
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        client.close()
        print("\n" + client.stats.describe())
        if client.indoor is not None:
            print("Последний статус: %s" % client.indoor.describe())
        if client.outdoor is not None:
            print("Последний статус: %s" % client.outdoor.describe())
        if rx["bytes"] == 0:
            print("Из линии не пришло ни одного байта. " + _SILENCE_HINT)
        reporter.close()

    return 0


def run_loopback(args) -> int:
    """Проверка адаптера и настроек порта без кондиционера.

    Отправляет заведомо корректный кадр и ждёт, вернётся ли он. При
    замкнутых на адаптере TX и RX кадр обязан прийти обратно и разобраться.
    Это отделяет неисправность адаптера, драйвера или параметров порта от
    проблем с линией до кондиционера.
    """
    transport = SerialTransport(
        port=args.port,
        baudrate=args.baud,
        parity=args.parity,
        timeout=0.1,
    )

    try:
        transport.open()
    except TransportError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        print("Список доступных портов: python aux_poll.py --list", file=sys.stderr)
        return 2

    probe = request_indoor()
    raw = probe.encode()
    timeout = args.duration if args.duration else 3.0

    print("Проверка порта %s на скорости %d, чётность %s."
          % (args.port, args.baud, args.parity))
    print("Замкните на адаптере TX и RX, иначе эху взяться неоткуда.")
    print("Отправляю: %s" % hexdump(raw))

    decoder = StreamDecoder()
    received = bytearray()
    packets = []
    try:
        transport.reset_input()
        transport.write(raw)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not packets:
            chunk = transport.read(256)
            if chunk:
                received.extend(chunk)
                packets.extend(decoder.feed(chunk))
            else:
                time.sleep(0.01)
    except TransportError as exc:
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        transport.close()

    if not received:
        print()
        print("Эха нет: за %.0f с не пришло ни одного байта." % timeout)
        print("Если перемычка TX-RX стоит, значит проблема в адаптере, драйвере")
        print("или в том, что порт занят другой программой.")
        return 1

    print("Принято %d байт: %s" % (len(received), hexdump(bytes(received))))
    if bytes(received) == raw and packets:
        print()
        print("Эхо совпало с отправленным, кадр разобран. Адаптер, драйвер и")
        print("параметры порта (%d/8-%s-1) исправны." % (args.baud, args.parity))
        print("Снимите перемычку и подключайтесь к кондиционеру.")
        return 0

    print()
    print("Байты пришли, но не совпали с отправленным.")
    print("Так бывает при неверной скорости или чётности: проверьте, что стоит")
    print("%d/8-%s-1, и что на линии нет второго передатчика." % (args.baud, args.parity))
    return 1


def run_rs485(args) -> int:
    """ЗАГОТОВКА: снятие дампа RS485-шины.

    Формат кадра RS485-интерфейса пока не описан (см.
    :mod:`aux_hvac.rs485_protocol`), поэтому здесь возможен только сбор
    сырого дампа с нарезкой по паузам в линии. Этого достаточно, чтобы
    подобрать скорость и увидеть границы посылок.
    """
    from aux_hvac.rs485_protocol import RS485Decoder
    from aux_hvac.transport.rs485 import COMMON_BAUDRATES

    transport = RS485Transport(
        port=args.port,
        baudrate=args.baud if args.baud != UART_BAUDRATE else 9600,
        parity=args.parity if args.parity != UART_PARITY else "N",
        timeout=args.read_timeout,
        address=args.address,
    )

    print("RS485: ЗАГОТОВКА. Формат кадра не расшифрован, идёт сбор сырого дампа.")
    print("Параметры: %r" % transport)
    print("Если в линии тишина, переберите скорости: %s" % ", ".join(map(str, COMMON_BAUDRATES)))
    print("Ctrl+C — остановка.\n")

    try:
        transport.open()
    except TransportError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        return 2

    decoder = RS485Decoder()
    dump = open(args.dump, "ab") if args.dump else None
    # пауза, после которой посылка считается законченной: как в Modbus RTU,
    # 3,5 байтовых времени, но не короче 2 мс
    gap = max(0.002, 3.5 * 10.0 / transport.baudrate)
    total = 0
    last_rx = time.monotonic()

    try:
        deadline = None if args.duration is None else time.monotonic() + args.duration
        while not _stop and (deadline is None or time.monotonic() < deadline):
            chunk = transport.read(256)
            now = time.monotonic()
            if chunk:
                total += len(chunk)
                decoder.feed(chunk)
                if dump is not None:
                    dump.write(chunk)
                last_rx = now
            else:
                if now - last_rx > gap:
                    for frame in decoder.flush():
                        print("%s %s" % (time.strftime("%H:%M:%S"), frame.describe()))
                time.sleep(0.002)
    except TransportError as exc:
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        for frame in decoder.flush():
            print("%s %s" % (time.strftime("%H:%M:%S"), frame.describe()))
        transport.close()
        if dump is not None:
            dump.close()
        print("\nПринято %d байт, посылок: %d." % (total, decoder.frames_seen))

    return 0


# ===========================================================================
#  CLI
# ===========================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aux_poll.py",
        description="Опрос кондиционера AUX через последовательный порт.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-l", "--list", action="store_true", help="показать доступные порты и выйти")
    parser.add_argument("-p", "--port", help="порт, например COM6 или /dev/ttyUSB0")
    parser.add_argument("-b", "--baud", type=int, default=UART_BAUDRATE, help="скорость (по умолчанию 4800)")
    parser.add_argument(
        "--parity",
        default=UART_PARITY,
        choices=["N", "E", "O", "M", "S"],
        help="чётность (по умолчанию E, как требует протокол AUX)",
    )
    parser.add_argument("--read-timeout", type=float, default=0.1, help="таймаут чтения порта, с")

    parser.add_argument("-a", "--active", action="store_true", help="эмулировать wifi-модуль")
    parser.add_argument("-i", "--interval", type=float, default=10.0, help="период запроса статусов, с")
    parser.add_argument("--no-ping", action="store_true", help="в активном режиме не отвечать на ping")
    parser.add_argument("-d", "--duration", type=float, help="сколько секунд работать (по умолчанию бесконечно)")
    parser.add_argument("--send", help="отправить произвольный кадр в hex перед началом опроса")
    parser.add_argument(
        "--loopback",
        action="store_true",
        help="проверить адаптер и порт: отправить кадр и дождаться эха (нужна перемычка TX-RX)",
    )

    parser.add_argument("--json", action="store_true", help="выводить состояния как JSON Lines")
    parser.add_argument("--log", help="дублировать вывод в файл")
    parser.add_argument("--dump", help="писать сырой поток в бинарный файл для offline-разбора")

    rs = parser.add_argument_group("RS485 (заготовка)")
    rs.add_argument("--rs485", action="store_true", help="работать с RS485-шиной вместо UART модуля")
    rs.add_argument("--sniff-raw", action="store_true", help="синоним --rs485 для наглядности")
    rs.add_argument("--address", type=lambda s: int(s, 0), default=0x01, help="адрес устройства на шине")

    return parser


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list:
        try:
            ports = list_ports()
        except TransportError as exc:
            print(exc, file=sys.stderr)
            return 2
        if not ports:
            print("Последовательные порты не найдены.")
            return 1
        for line in ports:
            print(line)
        return 0

    if not args.port:
        print("Не указан порт. Список доступных: python aux_poll.py --list", file=sys.stderr)
        return 2

    _install_sigint()

    try:
        if args.loopback:
            return run_loopback(args)
        if args.rs485 or args.sniff_raw:
            return run_rs485(args)
        return run_aux(args)
    except ValueError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
