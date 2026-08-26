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
    python aux_poll.py -p COM6 --status            прочитать текущий статус
    python aux_poll.py -p COM6 --watch             следить за изменениями (кнопки пульта)
    python aux_poll.py -p COM6 --monitor           живая панель состояния
    python aux_poll.py -p COM6 --set --power on    одиночная команда
    python aux_poll.py -p COM6 --set --byte 18=0x80  записать произвольный байт тела
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
import logging
import os
import re
import shutil
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
    Command,
    FanSpeed,
    IndoorState,
    Mode,
    OutdoorState,
    Packet,
    PacketType,
    RS485Transport,
    SerialTransport,
    StreamDecoder,
    TransportError,
    VerticalLouver,
    byte_names,
    crc16_bytes,
    decode_state,
    hexdump,
    list_ports,
    request_indoor,
    request_outdoor,
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


_MODES = {m.name.lower(): m for m in Mode}
_FANS = {f.name.lower(): f for f in FanSpeed}
_LOUVERS = {v.name.lower(): v for v in VerticalLouver}


def _ask(client, packet, want_cmd, timeout=5.0):
    """Отправляет запрос и ждёт информационный ответ на него."""
    client.decoder.reset()
    client.transport.reset_input()
    client.send(packet)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for pkt in client.poll_once():
            if pkt.ptype == PacketType.INFO and pkt.crc_ok and pkt.cmd == want_cmd:
                return pkt
        time.sleep(0.01)
    return None


def _print_state(indoor_pkt, outdoor_pkt):
    if indoor_pkt is not None:
        st = decode_state(indoor_pkt)
        print("  %s" % st.describe())
        print("  тело статуса: %s" % hexdump(st.payload))
    if outdoor_pkt is not None:
        print("  %s" % decode_state(outdoor_pkt).describe())


def _print_diff(before, after, title):
    """Печатает изменившиеся байты двух кадров одного типа."""
    if before is None or after is None:
        print("  %s: нет данных" % title)
        return
    names = byte_names(after)
    rows = [
        (8 + i, before.raw[8 + i], after.raw[8 + i])
        for i in range(min(len(before.body), len(after.body)))
        if before.raw[8 + i] != after.raw[8 + i]
    ]
    if not rows:
        print("  %s: без изменений" % title)
        return
    print("  %s:" % title)
    for idx, old, new in rows:
        print("    байт %-2d %-9s 0x%02X -> 0x%02X   %s -> %s"
              % (idx, names.get(idx, ""), old, new, format(old, "08b"), format(new, "08b")))


def _parse_byte_spec(spec):
    """Разбирает 'N=V': номер байта пакета (10..22) и значение."""
    if "=" not in spec:
        raise ValueError("ожидается вид N=V, например 18=0x80, получено %r" % spec)
    left, right = spec.split("=", 1)
    idx, val = int(left.strip(), 0), int(right.strip(), 0)
    if not 10 <= idx <= 22:
        raise ValueError("номер байта %d вне тела команды (допустимо 10..22)" % idx)
    if not 0 <= val <= 0xFF:
        raise ValueError("значение 0x%X не помещается в байт" % val)
    return idx, val


def _mutate(state, args):
    """Применяет к состоянию всё, что задано ключами командной строки."""
    changed = []
    simple = (
        ("power", state.set_power, lambda v: v == "on"),
        ("mode", state.set_mode, lambda v: _MODES[v]),
        ("fan", state.set_fan_speed, lambda v: _FANS[v]),
        ("temp", state.set_target_temp, float),
        ("louver", state.set_vertical_louver, lambda v: _LOUVERS[v]),
        ("swing_lr", state.set_swing_lr, lambda v: v == "on"),
        ("turbo", state.set_turbo, lambda v: v == "on"),
        ("mute", state.set_mute, lambda v: v == "on"),
        ("sleep", state.set_sleep, lambda v: v == "on"),
        ("display", state.set_display, lambda v: v == "on"),
        ("mildew", state.set_mildew, lambda v: v == "on"),
        ("health", state.set_health, lambda v: v == "on"),
        ("clean", state.set_clean, lambda v: v == "on"),
    )
    for name, setter, conv in simple:
        value = getattr(args, name, None)
        if value is not None:
            setter(conv(value))
            changed.append("%s=%s" % (name, value))
    if args.power_limit is not None:
        state.set_power_limit(None if args.power_limit < 0 else args.power_limit)
        changed.append("power_limit=%s" % args.power_limit)
    for spec in args.byte or []:
        idx, val = _parse_byte_spec(spec)
        state.payload[idx - 10] = val
        changed.append("байт %d=0x%02X" % (idx, val))
    return changed


def run_command(args) -> int:
    """Одиночная команда: прочитать статус, изменить, отправить, показать разницу."""
    transport = SerialTransport(args.port, baudrate=args.baud, parity=args.parity,
                                timeout=0.05)
    client = AuxClient(transport, active=True, poll_interval=1e9)

    try:
        client.open()
    except TransportError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        print("Список доступных портов: python aux_poll.py --list", file=sys.stderr)
        return 2

    try:
        before_in = _ask(client, request_indoor(), Command.INDOOR)
        before_out = _ask(client, request_outdoor(), Command.OUTDOOR)
        if before_in is None:
            print("Контроллер не ответил на запрос статуса.", file=sys.stderr)
            return 1

        print("СТАТУС:" if args.status else "БЫЛО:")
        _print_state(before_in, before_out)

        if args.status:
            return 0

        state = decode_state(before_in)
        changed = _mutate(state, args)
        if not changed:
            print("\nНи один параметр не задан — менять нечего. "
                  "Используйте --status для чтения.", file=sys.stderr)
            return 2

        cmd = state.to_command()
        print("\nОТПРАВЛЯЮ: %s" % ", ".join(changed))
        print("  кадр: %s" % hexdump(cmd.encode()))

        ack = _ask(client, cmd, Command.CONTROL)
        if ack is None:
            print("  подтверждение CMD=0x01 не получено", file=sys.stderr)
        else:
            ours = crc16_bytes(cmd.encode()[:-2])
            same = bytes(ack.body[2:4]) == ours
            print("  подтверждение: %s (CRC команды %s)"
                  % ("принято" if same else "CRC НЕ совпала", hexdump(ours)))

        time.sleep(args.settle)
        after_in = _ask(client, request_indoor(), Command.INDOOR)
        after_out = _ask(client, request_outdoor(), Command.OUTDOOR)

        print("\nСТАЛО:")
        _print_state(after_in, after_out)
        print()
        _print_diff(before_in, after_in, "изменения внутреннего блока CMD=0x11")
        _print_diff(before_out, after_out, "изменения внешнего блока  CMD=0x21")
        return 0
    except TransportError as exc:
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        client.close()


#: Байты, которые меняются сами по себе и в слежении только мешают.
_NOISY = {15, 17, 31}


def run_watch(args) -> int:
    """Следит за статусом и печатает только изменившиеся байты.

    Нужно, чтобы понять, что делает та или иная кнопка ИК-пульта: нажимаете
    кнопку и сразу видите, какой бит поехал.

    Отдельно отслеживается поле TMR байта 12 — счётчик минут с последней
    команды пульта. Любая команда с пульта обнуляет его, так что по нему
    видно сам факт приёма ИК-команды, даже если больше ничего не изменилось.
    """
    transport = SerialTransport(args.port, baudrate=args.baud, parity=args.parity,
                                timeout=0.05)
    client = AuxClient(transport, active=True, poll_interval=1e9)

    try:
        client.open()
    except TransportError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        print("Список доступных портов: python aux_poll.py --list", file=sys.stderr)
        return 2

    print("Слежение за статусом, порт %s, опрос раз в %g с."
          % (args.port, args.watch_interval))
    print("Нажимайте кнопки пульта по одной — изменившиеся байты появятся здесь.")
    if not args.all:
        print("Байты 15, 17 и 31 (температуры) скрыты как шум, показать: --all")
    print("Ctrl+C — остановка.")
    print()

    prev = {}
    ir_count = [0]
    deadline = None if args.duration is None else time.monotonic() + args.duration
    try:
        while not _stop and (deadline is None or time.monotonic() < deadline):
            for label, req, want in (("CMD=0x11", request_indoor(), Command.INDOOR),
                                     ("CMD=0x21", request_outdoor(), Command.OUTDOOR)):
                pkt = _ask(client, req, want, timeout=3.0)
                if pkt is None:
                    continue
                old = prev.get(label)
                prev[label] = pkt
                if old is None:
                    continue

                names = byte_names(pkt)
                rows = []
                for i in range(min(len(old.body), len(pkt.body))):
                    idx = 8 + i
                    a, b = old.raw[idx], pkt.raw[idx]
                    if a == b:
                        continue
                    if idx in _NOISY and not args.all:
                        continue
                    rows.append((idx, names.get(idx, ""), a, b))

                # Признаки команды с пульта. Счётчик минут байта 12 обнуляется
                # любой ИК-командой, но если он УЖЕ ноль, повторное нажатие в
                # ту же минуту по нему не видно. Поэтому вторым признаком берём
                # изменение любого байта настроек: в этом режиме мы сами команд
                # не отправляем, значит менять их может только пульт.
                ir = False
                if label == "CMD=0x11" and len(pkt.body) > 4:
                    was, now = old.raw[12] & 0x3F, pkt.raw[12] & 0x3F
                    ir = now < was
                    if any(i != 12 for i, _, _, _ in rows):
                        ir = True
                    elif (old.raw[12] & 0x80) != (pkt.raw[12] & 0x80):
                        ir = True
                    # подсказка: пока счётчик нулевой, следующее нажатие
                    # опознать по нему не получится
                    if was == 0 and now >= 1:
                        print("%s  --- счётчик минут дошёл до %d: можно нажимать "
                              "следующую кнопку ---" % (time.strftime("%H:%M:%S"), now))
                if ir:
                    ir_count[0] += 1
                    print()
                    print("%s  ===== ИК-КОМАНДА №%d ===== (счётчик минут байта 12 обнулён)"
                          % (time.strftime("%H:%M:%S"), ir_count[0]))
                for idx, name, a, b in rows:
                    print("%s  %s байт %-2d %-9s 0x%02X -> 0x%02X   %s -> %s"
                          % (time.strftime("%H:%M:%S"), label, idx, name, a, b,
                             format(a, "08b"), format(b, "08b")))
                if rows:
                    state = decode_state(pkt)
                    if state is not None:
                        print("             %s" % state.describe())
            time.sleep(max(0.0, args.watch_interval))
    except TransportError as exc:
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        client.close()
        print()
        print("Принято команд с пульта: %d." % ir_count[0])
        if ir_count[0]:
            print("Перечислите нажатые кнопки в том же порядке — номера совпадут.")
        print("Учтите: нажатие, которое ничего не меняет и приходит в ту же минуту,")
        print("что предыдущее, опознать невозможно — счётчик минут уже нулевой.")
        print("Жмите кнопку после строки «можно нажимать следующую кнопку».")
    return 0


#: Начало управляющей последовательности ANSI.
_CSI = chr(27) + "["


def _enable_ansi() -> bool:
    """Включает обработку ANSI в консоли. Возвращает True, если можно рисовать.

    В Windows виртуальный терминал в conhost по умолчанию выключен, и без
    этого вызова управляющие последовательности печатались бы как мусор.
    """
    if not sys.stdout.isatty():
        return False
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # 0x0004 — ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


class _Screen:
    """Держит кадр на месте, используя альтернативный буфер экрана.

    Подъём курсора на высоту кадра работает только пока кадр целиком влезает
    в окно. Стоит ему не влезть — терминал прокручивается, выше верхней
    строки курсор поднять нельзя, и каждый следующий кадр печатается на
    строку ниже: заголовок начинает дублироваться.

    Поэтому берём альтернативный буфер, как это делают top и htop. Он ведёт
    себя как окно фиксированного размера и не трогает основную прокрутку
    терминала — по выходе пользователь видит ровно то, что было до запуска.
    Кадр обрезается по размеру окна, чтобы прокрутки не возникало вовсе.
    """

    def __init__(self, ansi: bool) -> None:
        self.ansi = ansi
        self.entered = False
        self.last = []

    def start(self) -> None:
        if not self.ansi:
            return
        # ?1049h — альтернативный буфер, ?25l — скрыть курсор
        sys.stdout.write(_CSI + "?1049h" + _CSI + "?25l")
        sys.stdout.flush()
        self.entered = True

    def stop(self) -> None:
        if not self.entered:
            return
        sys.stdout.write(_CSI + "?25h" + _CSI + "?1049l")
        sys.stdout.flush()
        self.entered = False

    def draw(self, lines) -> None:
        self.last = list(lines)
        if not self.ansi:
            sys.stdout.write(chr(10).join(lines) + chr(10) * 2)
            sys.stdout.flush()
            return

        # get_terminal_size возвращает (columns, lines) — берём поля по
        # именам, чтобы не перепутать ширину с высотой
        size = shutil.get_terminal_size((80, 24))
        rows, cols = size.lines, size.columns
        body = list(lines)
        if len(body) > rows - 1:
            hidden = len(body) - (rows - 2)
            body = body[: rows - 2]
            body.append("  ... окно мало, скрыто строк: %d" % hidden)

        out = [_CSI + "H"]                      # курсор в левый верхний угол
        for line in body:
            out.append(line[: max(1, cols - 1)] + _CSI + "K" + chr(10))
        out.append(_CSI + "J")                  # погасить остаток экрана
        sys.stdout.write("".join(out))
        sys.stdout.flush()

    def replay_last(self) -> None:
        """Печатает последний кадр в обычный буфер, чтобы он остался на экране."""
        if self.last:
            sys.stdout.write(chr(10).join(self.last) + chr(10))
            sys.stdout.flush()


def _fmt_flag(value: bool, on: str = "ВКЛ", off: str = "выкл") -> str:
    return on if value else off


def _monitor_rows(ind_state, out_state, ind_pkt, out_pkt):
    """Собирает панель как список строк. Порядок и состав фиксированы."""
    rows = []
    rows.append(("h", "ВНУТРЕННИЙ БЛОК (CMD=0x11)", ""))
    if ind_state is None:
        rows.append(("v", "статус", "нет ответа"))
    else:
        st = ind_state
        rows += [
            ("v", "питание (б.18 бит5 POW)", _fmt_flag(st.power)),
            ("v", "режим (б.15 биты5-7 MD)", _name_of(st.mode)),
            ("v", "цель (б.10 биты3-7, б.12 бит7)", "%.1f °C" % st.target_temp),
            ("v", "вентилятор задан (б.13 биты5-7)", _name_of(st.fan_speed)),
            ("v", "TURBO (б.14 бит6 TB)", _fmt_flag(st.turbo)),
            ("v", "MUTE (б.14 бит7 MT)", _fmt_flag(st.mute)),
            ("v", "SLEEP (б.15 бит2 SLP)", _fmt_flag(st.sleep)),
            ("v", "iFeel (б.15 бит3 iFL)", _fmt_flag(st.ifeel)),
            ("v", "шторки верт. (б.10 биты0-2)", _name_of(st.vertical_louver)),
            ("v", "качание Л-П (б.11 биты5-7 LR)", _fmt_flag(st.swing_lr)),
            ("v", "дисплей (б.20 бит4 DS)", _fmt_flag(st.display)),
            ("v", "антиплесень (б.20 бит3 MD)", _fmt_flag(st.mildew)),
            ("v", "HEALTH (б.18 бит1 HL2)", _fmt_flag(st.health)),
            ("v", "таймер (б.18 бит6, б.13, б.14)", "%s, %d ч %02d мин"
                % (_fmt_flag(st.timer_enabled), st.timer_hours, st.timer_minutes)),
            ("v", "лимит мощности (б.21)", ("%d %%" % st.power_limit)
                if st.power_limit_enabled else "снят"),
            ("v", "минут с ИК-команды (б.12)", "%d" % st.minutes_since_ir),
            ("v", "тело статуса", hexdump(st.payload)),
        ]

    rows.append(("h", "ВНЕШНИЙ БЛОК (CMD=0x21)", ""))
    if out_state is None:
        rows.append(("v", "статус", "нет ответа"))
    else:
        st = out_state
        outdoor = "н/д" if st.outdoor_temp is None else "%.0f °C" % st.outdoor_temp
        compr = "н/д" if st.compressor_temp is None else "%.0f °C" % st.compressor_temp
        rows += [
            ("v", "питание (б.11 бит0 PWR)", _fmt_flag(st.power)),
            ("v", "режим (б.11 биты5-7 MD)", _name_of(st.mode)),
            ("v", "температура, байт 15+31", "%.1f °C" % st.indoor_temp),
            ("v", "теплообменник, байт 17", "%d  (%d °C по T-0x20)"
                % (st.return_temp_raw, st.return_temp_hint)),
            ("v", "снаружи, байт 20", outdoor),
            ("v", "компрессор, байт 22", compr),
            ("v", "скорость реальная (б.13)", _name_of(st.real_fan_speed)),
            ("v", "ШИМ вентилятора", "%d" % st.fan_pwm),
            ("v", "разморозка (б.12 бит5 DF)", _fmt_flag(st.defrost)),
            ("v", "iCLEAN (б.12 бит7 CL)", _fmt_flag(st.clean)),
            ("v", "мощность инвертора", "%d %%" % st.inverter_power),
            ("v", "ошибка", "0x%02X — %s" % (st.error_code, st.error_text)),
            ("v", "тело статуса", hexdump(st.payload)),
        ]
    return rows


def _name_of(value):
    return value.name if hasattr(value, "name") else "0x%02X" % value


def run_monitor(args) -> int:
    """Живая панель состояния: опрос по таймеру, перерисовка на месте."""
    transport = SerialTransport(args.port, baudrate=args.baud, parity=args.parity,
                                timeout=0.05)
    client = AuxClient(transport, active=True, poll_interval=1e9)

    try:
        client.open()
    except TransportError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        print("Список доступных портов: python aux_poll.py --list", file=sys.stderr)
        return 2

    ansi = _enable_ansi()
    screen = _Screen(ansi)
    if not ansi:
        print("Терминал не поддерживает ANSI: кадры будут идти друг за другом.")
    screen.start()

    previous = {}
    changed_at = {}
    started = time.monotonic()
    deadline = None if args.duration is None else started + args.duration

    try:
        while not _stop and (deadline is None or time.monotonic() < deadline):
            ind = _ask(client, request_indoor(), Command.INDOOR, timeout=3.0)
            out = _ask(client, request_outdoor(), Command.OUTDOOR, timeout=3.0)
            ind_state = decode_state(ind) if ind is not None else None
            out_state = decode_state(out) if out is not None else None

            now = time.monotonic()
            rows = _monitor_rows(ind_state, out_state, ind, out)

            lines = [
                "AUX HVAC — монитор   %s  %d/8-%s-1   %s   опрос %.1f с   Ctrl+C — выход"
                % (args.port, args.baud, args.parity, time.strftime("%H:%M:%S"),
                   args.monitor_interval),
                "",
            ]
            for kind, label, value in rows:
                if kind == "h":
                    lines.append("")
                    lines.append(label)
                    lines.append("-" * 64)
                    continue
                key = "%s|%s" % (len(lines), label)
                if key in previous and previous[key] != value:
                    changed_at[key] = now
                previous[key] = value
                fresh = now - changed_at.get(key, 0.0) < 3.0
                lines.append("  %-32s %-28s %s"
                             % (label, value, "<-- изменилось" if fresh else ""))

            lines.append("")
            lines.append("-" * 64)
            lines.append("  %s" % client.stats.describe())
            screen.draw(lines)

            time.sleep(max(0.05, args.monitor_interval))
    except TransportError as exc:
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        client.close()
        screen.stop()
        # альтернативный буфер по выходе исчезает вместе с панелью,
        # поэтому последний кадр печатаем ещё раз в обычный
        if ansi:
            screen.replay_last()
        sys.stdout.write(chr(10))
        sys.stdout.flush()
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

def _on_off(value: str) -> str:
    if value not in ("on", "off"):
        raise argparse.ArgumentTypeError("ожидается on или off, получено %r" % value)
    return value


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

    one = parser.add_argument_group(
        "одиночные команды",
        "прочитать статус, изменить заданное, отправить и показать разницу; "
        "скрипт сразу завершается",
    )
    one.add_argument("--status", action="store_true", help="только прочитать и показать статус")
    one.add_argument("--monitor", action="store_true",
                     help="живая панель состояния с перерисовкой на месте")
    one.add_argument("--monitor-interval", type=float, default=1.0,
                     help="период опроса в режиме --monitor, с (по умолчанию 1)")
    one.add_argument("--watch", action="store_true",
                     help="следить за статусом и печатать только изменения "
                          "(удобно для разбора кнопок ИК-пульта)")
    one.add_argument("--watch-interval", type=float, default=1.5,
                     help="период опроса в режиме --watch, с (по умолчанию 1.5); "
                          "общий --interval здесь не используется, он слишком "
                          "крупный и нажатия слипаются в один замер")
    one.add_argument("--all", action="store_true",
                     help="в режиме --watch не скрывать байты температур")
    one.add_argument("--set", action="store_true", dest="set_mode_flag",
                     help="отправить команду с параметрами ниже")
    one.add_argument("--settle", type=float, default=2.0,
                     help="пауза перед чтением результата, с (по умолчанию 2)")
    one.add_argument("--power", type=_on_off, help="включить/выключить")
    one.add_argument("--mode", choices=sorted(_MODES), help="режим работы")
    one.add_argument("--fan", choices=sorted(_FANS), help="скорость вентилятора")
    one.add_argument("--temp", type=float, help="целевая температура, шаг 0.5")
    one.add_argument("--louver", choices=sorted(_LOUVERS), help="вертикальные шторки")
    one.add_argument("--swing-lr", type=_on_off, help="качание влево-вправо")
    one.add_argument("--turbo", type=_on_off, help="интенсивный режим")
    one.add_argument("--mute", type=_on_off, help="тихий режим")
    one.add_argument("--sleep", type=_on_off, help="ночной режим")
    one.add_argument("--display", type=_on_off, help="дисплей")
    one.add_argument("--mildew", type=_on_off, help="антиплесень")
    one.add_argument("--health", type=_on_off, help="ионизатор HEALTH")
    one.add_argument("--clean", type=_on_off, help="самоочистка iCLEAN")
    one.add_argument("--power-limit", type=int,
                     help="лимит мощности инвертора, %% (отрицательное — снять)")
    one.add_argument("--byte", action="append", metavar="N=V",
                     help="записать произвольный байт тела, 10..22; можно повторять")

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="подробный лог обмена; предупреждения о неразобранных телах видны и без него",
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

    # без этого предупреждения библиотеки (например, о теле пакета, которое не
    # укладывается в описанный формат) уходили бы в пустоту
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

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
        if args.monitor:
            return run_monitor(args)
        if args.watch:
            return run_watch(args)
        if args.status or args.set_mode_flag:
            return run_command(args)
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
