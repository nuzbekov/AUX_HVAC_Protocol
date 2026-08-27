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
    python aux_poll.py --sweep -p COM6 --rs485-port COM9
                                                        активный проход по величинам
    python aux_poll.py --correlate -p COM6 --rs485-port COM9
                                                        сопоставить регистры шины
                                                        с полями UART
    python aux_poll.py -p COM6 --rs485                   слушать шину RS485
    python aux_poll.py -p COM6 --rs485 --monitor         живая панель регистров шины
    python aux_poll.py -p COM6 --rs485 --dump rs485.bin  дамп шины в файл

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
from aux_hvac.transport.rs485 import (  # noqa: E402
    RS485_BAUDRATE,
    RS485_PARITY,
)

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


def _parse_timer_spec(spec):
    """Разбирает значение --timer: 'Ч:ММ' либо 'off'.

    По README часы лежат в битах 0..4 байта 13 (максимум 23), минуты — в
    битах 0..4 байта 14 (максимум 31), а сам таймер включается битом TMR
    байта 18.
    """
    if spec.strip().lower() in ("off", "выкл", "0"):
        return None
    text = spec.replace(".", ":").strip()
    if ":" not in text:
        raise ValueError("ожидается вид Ч:ММ или off, получено %r" % spec)
    hh, mm = text.split(":", 1)
    hours, minutes = int(hh), int(mm)
    if not 0 <= hours <= 23:
        raise ValueError("часы таймера %d вне диапазона 0..23" % hours)
    if not 0 <= minutes <= 31:
        raise ValueError("минуты таймера %d вне диапазона 0..31 "
                         "(в поле всего 5 бит)" % minutes)
    return hours, minutes


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
    if args.timer is not None:
        parsed = _parse_timer_spec(args.timer)
        if parsed is None:
            state.clear_timer()
            changed.append("таймер выключен полностью (задержка, бит TMR, бит 7)")
        else:
            hours, minutes = parsed
            state.set_timer(hours, minutes, enabled=True)
            changed.append("таймер %d:%02d" % (hours, minutes))
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
            ("v", "таймер (б.18 бит6, б.13, б.14)", st.describe_timer()),
            ("v", "байт 18 бит7 (не расшифрован)", _fmt_flag(st.en_bit7, "1", "0")),
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
            ("v", "температура возд., байт 15+31", "%.1f °C" % st.indoor_temp),
            ("v", "теплообменник, байт 17", "%d °C  (сырое 0x%02X)"
                % (st.return_temp_hint, st.return_temp_raw)),
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
            for row in client.stats.describe_lines():
                lines.append("  %s" % row)
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


#: Диапазон, в котором подсказка «столько-то градусов» осмысленна.
#:
#: Печатать её для каждого регистра нельзя: ноль превратится в «0.0 °C», а
#: значение 17 — в «1.7 °C», и панель начнёт выдавать догадки за показания.
#: Поэтому для нерасшифрованных регистров подсказка появляется только внутри
#: правдоподобного для датчика диапазона. Для расшифрованных — всегда.
RS485_PLAUSIBLE_TEMP = (50, 1000)   # 5,0 .. 100,0 градуса


def _rs485_value(block, cmd, reg, value):
    """Значение регистра для панели: число и, если уместно, градусы."""
    from aux_hvac.rs485_protocol import KNOWN_REGISTERS

    temp = block.as_celsius(value)
    known = (cmd, reg) in KNOWN_REGISTERS
    low, high = RS485_PLAUSIBLE_TEMP
    if temp is not None and (known or low <= abs(value) <= high):
        return "%6d   %.1f °C" % (value, temp)
    return "%6d" % value


try:
    from aux_hvac.rs485_protocol import KNOWN_REGISTERS as KNOWN_REGISTERS_CACHE
except ImportError:                                   # pragma: no cover
    KNOWN_REGISTERS_CACHE = {}


def _rs485_registers(seen):
    """Собирает строки панели из последних кадров каждого вида.

    Кадры сгруппированы по адресам, команде и индексу блока: у каждой группы
    свои регистры, и в панели они идут отдельными разделами. Расшифрованные
    регистры подписываются.

    Кадры без блока регистров (опросы и прочее) сведены в один компактный
    раздел в конце по строке на вид. Иначе они занимают по разделу каждый, и
    панель перестаёт влезать в окно — а интересное в ней как раз выше.

    Возвращает строки вида (тип, ключ, подпись, значение). Ключ нужен, чтобы
    отметка «изменилось» считалась внутри своей группы: подписи вроде
    «регистр 11» повторяются в разных группах, и по одной подписи значения
    разных кадров затирали бы друг друга.
    """
    rows, plain = [], []
    for key in sorted(seen):
        frame, stamp, count = seen[key]
        tag = "%02X %02X cmd=%02X" % (frame.addr_a, frame.addr_b, frame.cmd)
        block = frame.block
        if block is None:
            plain.append((key, tag, hexdump(frame.payload) or "пусто", count))
            continue
        rows.append(("h", None,
                     "%s   регистры %d..%d   кадров %d   последний %s"
                     % (tag, block.index, block.index + block.count - 1, count,
                        time.strftime("%H:%M:%S", time.localtime(stamp))), ""))
        for reg, value in block.items():
            name = KNOWN_REGISTERS_CACHE.get((frame.cmd, reg))
            label = ("регистр %d" % reg if name is None
                     else "регистр %d — %s" % (reg, name))
            rows.append(("v", (key, reg), label,
                         _rs485_value(block, frame.cmd, reg, value)))

    if plain:
        rows.append(("h", None, "кадры без блока регистров", ""))
        for key, tag, payload, count in plain:
            rows.append(("v", (key, "raw"), "%s   кадров %d" % (tag, count), payload))
    return rows


def _rs485_monitor(args, transport) -> int:
    """Живая панель шины RS485: перерисовка на месте, отметка изменений.

    Шину только слушаем: на ней уже есть мастер, и опрашивать самим не нужно
    и не стоит. Поэтому период обновления — это период перерисовки панели, а
    не период опроса: кадры приходят сами, своим циклом.
    """
    from aux_hvac.rs485_protocol import BusState, RS485Decoder

    decoder = RS485Decoder()
    state = BusState()
    dump = open(args.dump, "ab") if args.dump else None

    ansi = _enable_ansi()
    screen = _Screen(ansi)
    if not ansi:
        print("Терминал не поддерживает ANSI: кадры будут идти друг за другом.")
    screen.start()

    seen = {}          # (адреса, команда, индекс блока) -> (кадр, время, счёт)
    previous = {}
    changed_at = {}
    total = 0
    started = time.monotonic()
    deadline = None if args.duration is None else started + args.duration
    next_draw = 0.0

    try:
        while not _stop and (deadline is None or time.monotonic() < deadline):
            chunk = transport.read(256)
            if chunk:
                total += len(chunk)
                if dump is not None:
                    dump.write(chunk)
                for frame in decoder.feed(chunk):
                    state.update(frame)
                    key = (frame.addr_a, frame.addr_b, frame.cmd,
                           bytes(frame.payload[:2]))
                    count = seen[key][2] + 1 if key in seen else 1
                    seen[key] = (frame, time.time(), count)

            now = time.monotonic()
            if now < next_draw:
                if not chunk:
                    time.sleep(0.002)
                continue
            next_draw = now + max(0.05, args.monitor_interval)

            lines = [
                "AUX RS485 — монитор   %s  %d/8-%s-1   %s   обновление %.1f с   "
                "Ctrl+C — выход"
                % (args.port, args.baud, args.parity, time.strftime("%H:%M:%S"),
                   args.monitor_interval),
                "",
            ]

            # состояние блока идёт первым и построчно: в длинной строке его
            # не найти глазами среди десятков строк регистров
            lines.append("СОСТОЯНИЕ БЛОКА")
            lines.append("-" * 68)
            if not state.seen_state_frame:
                lines.append("  кадр CMD=0x01 ещё не приходил — состояние неизвестно")
                lines.append("  (он идёт через цикл, подождите несколько секунд)")
            for label, value, source in state.rows():
                mark = ""
                key = ("state", label)
                if key in previous:
                    if previous[key] != value:
                        changed_at[key] = now
                    if now - changed_at.get(key, 0.0) < 5.0:
                        mark = "<-- изменилось"
                previous[key] = value
                lines.append("  %-16s %-22s %-26s %s"
                             % (label, value, source, mark))
            lines.append("")
            if not seen:
                lines.append("  Пока ни одного кадра. Если в линии тишина —")
                lines.append("  проверьте скорость и подключение A/B.")
            for kind, key, label, value in _rs485_registers(seen):
                if kind == "h":
                    lines.append("")
                    lines.append(label)
                    lines.append("-" * 68)
                    continue
                mark = ""
                if key in previous:
                    if previous[key] != value:
                        changed_at[key] = now
                    if now - changed_at.get(key, 0.0) < 5.0:
                        mark = "<-- изменилось"
                previous[key] = value
                lines.append("  %-40s %-18s %s" % (label, value, mark))

            lines.append("")
            lines.append("-" * 68)
            lines.append("  принято %d байт, кадров %d, битых CRC %d, мусорных байт %d"
                         % (total, decoder.frames_seen, decoder.bad_crc,
                            decoder.dropped_bytes))
            lines.append("  видов кадров: %d, работаем %.0f с"
                         % (len(seen), now - started))
            screen.draw(lines)
    except TransportError as exc:
        screen.stop()
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        screen.stop()
        decoder.flush()
        transport.close()
        if dump is not None:
            dump.close()

    print("Принято %d байт, кадров %d, битых CRC %d, мусорных байт %d."
          % (total, decoder.frames_seen, decoder.bad_crc, decoder.dropped_bytes))
    return 0


#: Период запроса статуса при сопоставлении, секунды.
#:
#: Клиент чередует запросы внутреннего и внешнего блоков, поэтому статус
#: каждого вида приходит вдвое реже. 3,5 с здесь дают 7 с на каждый вид —
#: ровно столько, сколько ждёт между запросами эталонная реализация
#: GrKoR/esphome_aux_ac_component (AC_STATES_REQUEST_INTERVAL = 7000).
CORRELATE_POLL_INTERVAL = 3.5


#: Шаги активного прохода: что менять и в каком порядке.
#:
#: Каждый шаг меняет РОВНО ОДНУ величину — в этом весь смысл: если после шага
#: поехал регистр, причина однозначна. Величины перебираются группами, и
#: каждая группа заканчивается возвратом к исходному значению, чтобы
#: следующая группа начиналась с одного и того же состояния.
#:
#: Уставка идёт первой и с большим размахом: это самый вероятный кандидат на
#: регистры 11 и 12, которые в дампе держали 20,0.
SWEEP_STEPS = (
    ("питание включено",        "power", True),
    ("уставка 20",              "target_temp", 20.0),
    ("уставка 24",              "target_temp", 24.0),
    ("уставка 28",              "target_temp", 28.0),
    ("уставка 17",              "target_temp", 17.0),
    ("уставка 22,5",            "target_temp", 22.5),
    ("уставка 20",              "target_temp", 20.0),
    ("режим COOL",              "mode", "cool"),
    ("режим HEAT",              "mode", "heat"),
    ("режим FAN",               "mode", "fan"),
    ("режим DRY",               "mode", "dry"),
    ("режим AUTO",              "mode", "auto"),
    ("вентилятор LOW",          "fan", "low"),
    ("вентилятор MEDIUM",       "fan", "medium"),
    ("вентилятор HIGH",         "fan", "high"),
    ("вентилятор AUTO",         "fan", "auto"),
    # Логические величины переключаются дважды туда и обратно. Одного
    # переключения мало: если величина уже была в нужном состоянии, команда
    # ничего не меняет, перехода не происходит, и соответствие остаётся
    # недоказанным. Именно так дисплей попадал в догадки.
    ("дисплей включён",         "display", True),
    ("дисплей выключен",        "display", False),
    ("дисплей включён",         "display", True),
    ("дисплей выключен",        "display", False),
    ("дисплей включён",         "display", True),
    # TURBO нужен режим, в котором он вообще применим
    ("режим COOL для TURBO",    "mode", "cool"),
    ("TURBO включён",           "turbo", True),
    ("TURBO выключен",          "turbo", False),
    ("TURBO включён",           "turbo", True),
    ("TURBO выключен",          "turbo", False),
    ("SLEEP включён",           "sleep", True),
    ("SLEEP выключен",          "sleep", False),
    ("SLEEP включён",           "sleep", True),
    ("SLEEP выключен",          "sleep", False),
    ("шторки STOP",             "louver", "stop"),
    ("шторки SWING",            "louver", "swing"),
    ("шторки STOP",             "louver", "stop"),
    ("шторки SWING",            "louver", "swing"),
    ("питание выключено",       "power", False),
    ("питание включено",        "power", True),
    ("питание выключено",       "power", False),
    ("питание включено",        "power", True),
)

#: Сколько ждать после команды, прежде чем считать шину обновившейся.
#:
#: Цикл опроса шины в дампе занимал секунды, поэтому берём с запасом: лучше
#: подождать, чем приписать изменение не тому шагу.
SWEEP_SETTLE = 6.0


def _sweep_apply(client, state, what, value):
    """Применяет одно изменение к состоянию. Возвращает описание или None."""
    if what == "power":
        state.set_power(bool(value))
    elif what == "target_temp":
        state.set_target_temp(float(value))
    elif what == "mode":
        state.set_mode(Mode[value.upper()])
    elif what == "fan":
        state.set_fan_speed(FanSpeed[value.upper()])
    elif what == "display":
        state.set_display(bool(value))
    elif what == "turbo":
        state.set_turbo(bool(value))
    elif what == "sleep":
        state.set_sleep(bool(value))
    elif what == "louver":
        state.set_vertical_louver(VerticalLouver[value.upper()])
    else:
        return None
    return "%s = %s" % (what, value)


def _sweep_collect(client, bus, decoder, corr, seconds, log_rows=None):
    """Обновляет статусы UART, затем слушает шину заданное время.

    Запрос статусов здесь обязателен: информационные пакеты кондиционер сам
    не присылает, только в ответ на запрос. Без свежего статуса коррелятор
    снимок не возьмёт — сопоставлять регистры будет не с чем.

    Запрашиваются оба статуса. Большой (CMD=0x21) нужен даже в первую
    очередь: комнатная и внешняя температуры лежат именно в нём, а это самые
    ценные величины для сопоставления.
    """
    for packet, want in ((request_indoor(), Command.INDOOR),
                         (request_outdoor(), Command.OUTDOOR)):
        # ответ разбирается внутри poll_once, а on_state отдаёт его коррелятору
        _ask(client, packet, want, timeout=3.0)

    deadline = time.monotonic() + seconds
    while not _stop and time.monotonic() < deadline:
        client.poll_once()
        chunk = bus.read(256)
        if chunk:
            for frame in decoder.feed(chunk):
                block = frame.block
                if block is not None:
                    taken = corr.add_registers(time.monotonic(), frame.cmd,
                                               block.index, block.values)
                    if taken and log_rows is not None:
                        log_rows.append((frame.cmd, block.index, list(block.values)))
                elif frame.payload:
                    # нагрузка не разобралась как блок регистров, но данные в
                    # ней есть: у CMD=0x01 она менялась вслед за уставкой
                    corr.add_payload(time.monotonic(), frame.cmd, frame.payload)
        else:
            time.sleep(0.002)


def _corr_where(cmd, reg):
    """Название места величины в кадре, через модуль сопоставления."""
    from aux_hvac.correlate import where

    return where(cmd, reg)


def run_sweep(args) -> int:
    """Активный проход по величинам: меняем по одной по UART, смотрим шину.

    Это ускоренный вариант расшифровки регистров. Пассивное сопоставление
    (:func:`run_correlate`) ждёт, пока величины подвигает человек; здесь
    скрипт двигает их сам, по одной за шаг, и после каждого шага сообщает,
    какие регистры шины поехали. Причина изменения при этом однозначна.

    Перед каждым шагом статус перезапрашивается, а команда собирается из
    свежего статуса — так требует протокол (README, «Последовательности
    команд»), иначе командой можно затереть то, что изменилось само.
    """
    from aux_hvac.correlate import Correlator
    from aux_hvac.rs485_protocol import RS485Decoder

    if not args.rs485_port:
        print("Не указан порт шины: --rs485-port COM9", file=sys.stderr)
        return 2

    uart = SerialTransport(args.port, baudrate=args.baud, parity=args.parity,
                           timeout=0.05)
    bus = RS485Transport(args.rs485_port, baudrate=RS485_BAUDRATE,
                         parity=RS485_PARITY, timeout=0.05)
    client = AuxClient(uart, active=True, poll_interval=1e9)
    corr = Correlator(min_samples=3)
    client.on_state = lambda state, packet: corr.add_uart(time.monotonic(), state)

    try:
        client.open()
    except TransportError as exc:
        print("Ошибка порта UART %s: %s" % (args.port, exc), file=sys.stderr)
        return 2
    try:
        bus.open()
    except TransportError as exc:
        client.close()
        print("Ошибка порта шины %s: %s" % (args.rs485_port, exc), file=sys.stderr)
        return 2

    decoder = RS485Decoder()
    log = open(args.log, "a", encoding="utf-8") if args.log else None
    settle = args.sweep_settle

    def bus_snapshot():
        """Последние значения всех регистров шины."""
        out = {}
        for sample in corr.samples:
            out.update(sample.regs)
        return out

    print("Активный проход: %d шагов, по %.0f с на шаг, это примерно %.0f мин."
          % (len(SWEEP_STEPS), settle, len(SWEEP_STEPS) * settle / 60.0))
    print("UART %s (%d/8-%s-1), шина %s (%d/8-%s-1)."
          % (args.port, args.baud, args.parity,
             args.rs485_port, RS485_BAUDRATE, RS485_PARITY))
    print("Каждый шаг меняет ровно одну величину. Ctrl+C — остановка.")
    print("")

    rc = 0
    try:
        # исходный срез: даём шине и UART заговорить
        print("Слушаю оба интерфейса %.0f с до первой команды..." % settle)
        _sweep_collect(client, bus, decoder, corr, settle)
        if not corr.samples:
            print("")
            print("Ни одного снимка: значит молчит хотя бы один из интерфейсов.",
                  file=sys.stderr)
            print("Проверьте по отдельности:", file=sys.stderr)
            print("  - идут ли кадры с шины: python aux_poll.py -p %s --rs485"
                  % args.rs485_port, file=sys.stderr)
            print("  - отвечает ли кондиционер по UART: python aux_poll.py -p %s --status"
                  % args.port, file=sys.stderr)
            return 1
        print("Снимков набрано: %d, кадров с шины: %d."
              % (len(corr.samples), decoder.frames_seen))
        print("")

        before = bus_snapshot()
        for number, (title, what, value) in enumerate(SWEEP_STEPS, 1):
            if _stop:
                break
            packet = _ask(client, request_indoor(), Command.INDOOR, timeout=3.0)
            if packet is None:
                print("%2d. %-22s статус не пришёл, шаг пропущен" % (number, title))
                continue
            state = decode_state(packet)
            described = _sweep_apply(client, state, what, value)
            if described is None:
                continue
            client.apply(state)

            _sweep_collect(client, bus, decoder, corr, settle)
            after = bus_snapshot()
            moved = [(key, before[key], after[key]) for key in sorted(after)
                     if key in before and before[key] != after[key]]
            before = after

            if moved:
                shown = "; ".join(
                    "%s: %d -> %d" % (_corr_where(key[0], key[1]), was, now)
                    for key, was, now in moved)
            else:
                shown = "на шине без изменений"
            print("%2d. %-22s %s" % (number, title, shown))
            if log is not None:
                log.write(json.dumps({
                    "step": number, "title": title,
                    "change": {"what": what, "value": value},
                    "moved": [{"cmd": k[0], "reg": k[1], "was": w, "now": n}
                              for k, w, n in moved],
                }, ensure_ascii=False) + chr(10))
                log.flush()
    except TransportError as exc:
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        rc = 2
    finally:
        decoder.flush()
        client.close()
        bus.close()
        if log is not None:
            log.close()

    print("")
    print("Шина: кадров %d, битых CRC %d, мусорных байт %d."
          % (decoder.frames_seen, decoder.bad_crc, decoder.dropped_bytes))
    print("UART: %s" % client.stats.describe())
    print("")
    print("=== ИТОГ СОПОСТАВЛЕНИЯ ===")
    for line in corr.report_lines():
        print(line)
    return rc


def run_correlate(args) -> int:
    """Слушает оба интерфейса сразу и сопоставляет регистры шины с полями UART.

    Смысл: у платы два интерфейса, и семантика известна только у одного. Если
    слушать их одновременно, каждое изменение любой величины сразу даёт пару
    «известное поле UART — неизвестный регистр RS485». Одна сессия закрывает
    столько регистров, сколько величин успели подвигаться, вместо одного
    регистра за пару дампов.

    По UART работаем активно (изображаем wifi-модуль и запрашиваем статусы),
    по шине — только слушаем: там уже есть свой мастер.
    """
    from aux_hvac.correlate import Correlator
    from aux_hvac.rs485_protocol import RS485Decoder

    if not args.rs485_port:
        print("Не указан порт шины. Пример:", file=sys.stderr)
        print("  python aux_poll.py --correlate -p COM6 --rs485-port COM9",
              file=sys.stderr)
        return 2
    if args.rs485_port == args.port:
        print("Порты UART и шины совпадают (%s) — это два разных интерфейса."
              % args.port, file=sys.stderr)
        return 2

    uart = SerialTransport(args.port, baudrate=args.baud, parity=args.parity,
                           timeout=0.05)
    bus = RS485Transport(args.rs485_port, baudrate=RS485_BAUDRATE,
                         parity=RS485_PARITY, timeout=0.05)
    client = AuxClient(uart, active=True,
                       poll_interval=args.correlate_interval)
    corr = Correlator()

    def on_state(state, packet):
        corr.add_uart(time.monotonic(), state)

    client.on_state = on_state

    try:
        client.open()
    except TransportError as exc:
        print("Ошибка порта UART %s: %s" % (args.port, exc), file=sys.stderr)
        return 2
    try:
        bus.open()
    except TransportError as exc:
        client.close()
        print("Ошибка порта шины %s: %s" % (args.rs485_port, exc), file=sys.stderr)
        return 2

    decoder = RS485Decoder()
    log = open(args.log, "a", encoding="utf-8") if args.log else None
    ansi = _enable_ansi()
    screen = _Screen(ansi)
    if not ansi:
        print("Терминал не поддерживает ANSI: кадры будут идти друг за другом.")
    screen.start()

    started = time.monotonic()
    deadline = None if args.duration is None else started + args.duration
    next_draw = 0.0
    bus_bytes = 0

    try:
        while not _stop and (deadline is None or time.monotonic() < deadline):
            client.poll_once()

            chunk = bus.read(256)
            if chunk:
                bus_bytes += len(chunk)
                for frame in decoder.feed(chunk):
                    block = frame.block
                    if block is None:
                        if frame.payload:
                            corr.add_payload(time.monotonic(), frame.cmd,
                                             frame.payload)
                        continue
                    taken = corr.add_registers(time.monotonic(), frame.cmd,
                                               block.index, block.values)
                    if taken and log is not None:
                        log.write(json.dumps({
                            "t": round(time.monotonic() - started, 3),
                            "cmd": frame.cmd,
                            "index": block.index,
                            "values": block.values,
                            "uart": corr.samples[-1].uart,
                        }, ensure_ascii=False) + chr(10))
                        log.flush()

            now = time.monotonic()
            if now < next_draw:
                if not chunk:
                    time.sleep(0.002)
                continue
            next_draw = now + max(0.2, args.monitor_interval)

            moved_regs = corr.moved_registers()
            moved_flds = corr.moved_fields()
            found = corr.matches()

            lines = [
                "AUX сопоставление   UART %s  <->  шина %s   %s   Ctrl+C — выход"
                % (args.port, args.rs485_port, time.strftime("%H:%M:%S")),
                "",
                "  снимков %d, статусов UART %s, кадров шины %d, работаем %.0f с"
                % (len(corr.samples),
                   "нет" if not corr.samples else "есть",
                   decoder.frames_seen, now - started),
                "  подвигалось: полей UART %d, регистров шины %d"
                % (len(moved_flds), len(moved_regs)),
                "",
                "СОПОСТАВЛЕНО",
                "-" * 70,
            ]
            if found:
                for match in found:
                    lines.append("  " + match.describe())
            else:
                lines.append("  пока ничего")

            lines.append("")
            lines.append("ПОДВИГАЛОСЬ, НО НЕ СОШЛОСЬ")
            lines.append("-" * 70)
            matched = {(m.cmd, m.reg) for m in found}
            silent = [k for k in moved_regs if k not in matched]
            if silent:
                for cmd, reg in silent[:12]:
                    values = moved_regs[(cmd, reg)]
                    shown = ", ".join(str(v) for v in values[:6])
                    if len(values) > 6:
                        shown += ", ..."
                    lines.append("  cmd=%02X рег %-3d  %s" % (cmd, reg, shown))
            else:
                lines.append("  таких регистров нет")

            lines.append("")
            lines.append("ЧТО ПОКРУТИТЬ НА ПУЛЬТЕ")
            lines.append("-" * 70)
            todo = [n for n in ("target_temp", "mode", "fan_speed", "power",
                                "vertical_louver", "turbo", "sleep", "display")
                    if n not in moved_flds]
            lines.append("  ещё не менялось: %s"
                         % (", ".join(todo) if todo else "всё перечисленное уже двигали"))
            screen.draw(lines)
    except TransportError as exc:
        screen.stop()
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        screen.stop()
        decoder.flush()
        client.close()
        bus.close()
        if log is not None:
            log.close()

    print("Байт с шины: %d, кадров %d, битых CRC %d, мусорных байт %d."
          % (bus_bytes, decoder.frames_seen, decoder.bad_crc,
             decoder.dropped_bytes))
    print("UART: %s" % client.stats.describe())
    print("")
    for line in corr.report_lines():
        print(line)
    return 0


def run_rs485(args) -> int:
    """ЗАГОТОВКА: снятие дампа RS485-шины.

    Формат кадра RS485-интерфейса пока не описан (см.
    :mod:`aux_hvac.rs485_protocol`), поэтому здесь возможен только сбор
    сырого дампа с нарезкой по паузам в линии. Этого достаточно, чтобы
    подобрать скорость и увидеть границы посылок.
    """
    from aux_hvac.rs485_protocol import BusState, RS485Decoder
    from aux_hvac.transport.rs485 import COMMON_BAUDRATES

    transport = RS485Transport(
        port=args.port,
        baudrate=args.baud,
        parity=args.parity,
        timeout=args.read_timeout,
        address=args.address,
    )

    print("RS485: пассивное прослушивание шины, разбор кадров 0x7E.")
    print("Параметры: %r" % transport)
    print("Если в линии тишина, переберите скорости: %s" % ", ".join(map(str, COMMON_BAUDRATES)))
    print("Смысл регистров не расшифрован, они выводятся как индекс=значение.")
    print("Ctrl+C — остановка.\n")

    try:
        transport.open()
    except TransportError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        return 2

    if args.monitor:
        return _rs485_monitor(args, transport)

    decoder = RS485Decoder()
    state = BusState()
    dump = open(args.dump, "ab") if args.dump else None
    total = 0
    # кадры идут одинаковыми циклами, поэтому по умолчанию печатаем только
    # новые и изменившиеся: иначе повторы заливают экран и настоящее
    # изменение регистра в них теряется
    seen = {}

    try:
        deadline = None if args.duration is None else time.monotonic() + args.duration
        while not _stop and (deadline is None or time.monotonic() < deadline):
            chunk = transport.read(256)
            if not chunk:
                time.sleep(0.002)
                continue
            total += len(chunk)
            if dump is not None:
                dump.write(chunk)
            for frame in decoder.feed(chunk):
                state.update(frame)
                # кадр опознаём по адресам, команде и индексу блока: тогда
                # изменение значений регистров видно как изменение кадра
                key = (frame.addr_a, frame.addr_b, frame.cmd, bytes(frame.payload[:2]))
                if not args.verbose and seen.get(key) == frame.payload:
                    continue
                mark = "*" if key in seen else " "   # * — кадр изменился
                seen[key] = frame.payload
                print("%s%s %s" % (time.strftime("%H:%M:%S"), mark, frame.describe()))
    except TransportError as exc:
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        decoder.flush()
        transport.close()
        if dump is not None:
            dump.close()
        print("\n" + state.describe())
        print("Принято %d байт, кадров: %d, битых CRC: %d, мусорных байт: %d."
              % (total, decoder.frames_seen, decoder.bad_crc, decoder.dropped_bytes))
        if not args.verbose:
            print("Печатались только новые и изменившиеся кадры; -v — печатать все.")

    return 0


#: Сколько секунд линия должна молчать, чтобы считать её свободной.
#:
#: Мастер шлёт кадры пачкой: между соседними кадрами пачки пауз почти нет,
#: а между пачками — секунды. Пауза в четверть длительности самого короткого
#: кадра (10 байт на 9600 это около 10 мс) надёжно отделяет одно от другого,
#: не дожидаясь конца всей пачки.
PROBE_IDLE = 0.05

#: Во сколько раз ответы должны участиться, чтобы поверить, что плата
#: услышала именно нас.
#:
#: Штатный цикл сам по себе слегка плавает, поэтому небольшой разброс ни о
#: чём не говорит. Полуторакратный рост случайным дрожанием не объяснить.
PROBE_RATE_FACTOR = 1.5

#: Сколько ждать ответа после своего кадра.
#:
#: Собственные ответы платы приходят сразу за опросом, в пределах десятков
#: миллисекунд. Полсекунды — с запасом, и при этом мы успеваем отдать линию
#: до следующей пачки мастера.
PROBE_WAIT = 0.5


def run_rs485_probe_collide(args) -> int:
    """Проверка передатчика столкновением: не зависит от того, слышит ли плата.

    Шлёт короткий кадр НЕ дожидаясь паузы — специально поверх идущей по шине
    передачи. Если наш сигнал реально ложится на линию, CRC у кого-то из
    участников штатного цикла перестанет сходиться прямо во время передачи.
    Если нет — испорченных кадров не прибавится, сколько ни пытайся.

    Кадр умышленно совсем короткий (доля от 10 байт минимального кадра
    шины), чтобы почти наверняка угодить внутрь чужой передачи, а не в
    паузу перед ней.
    """
    from aux_hvac.rs485_protocol import RS485Decoder

    transport = RS485Transport(
        port=args.port, baudrate=args.baud, parity=args.parity,
        timeout=args.read_timeout, address=args.address,
    )
    print("RS485: проверка передатчика столкновением.")
    print("Параметры: %r" % transport)
    print("Шлём короткий мусор поверх чужих передач и смотрим, портится ли "
          "их CRC.")
    print("Ctrl+C — остановка.\n")

    try:
        transport.open()
    except TransportError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        return 2

    decoder = RS485Decoder()
    garbage = bytes([0xFF, 0x00, 0xFF, 0x00])
    total_frames = total_bad = 0
    hits = tries = 0

    try:
        deadline = time.monotonic() + args.probe_collide
        while not _stop and time.monotonic() < deadline:
            before_bad = decoder.bad_crc
            transport.write(garbage)
            tries += 1
            chunk = transport.read(64)
            if chunk:
                decoder.feed(chunk)
            if decoder.bad_crc > before_bad:
                hits += 1
            time.sleep(0.003)
        total_frames, total_bad = decoder.frames_seen, decoder.bad_crc
    except TransportError as exc:
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        decoder.flush()
        transport.close()

    print("Передач: %d, кадров разобрано: %d, из них с несошедшейся CRC: %d"
          % (tries, total_frames, total_bad))
    if total_bad:
        print("\nCRC портится — значит наш сигнал реально ложится на линию. "
              "Передатчик работает.")
        print("Если при этом --rs485-probe ответа не даёт, дело не в "
              "передатчике: плата либо")
        print("отвечает не всякому адресу, либо не отвечает на запрос "
              "вообще.")
        return 0

    print("\nЗа всё время ни одна CRC не испортилась. Похоже, наш сигнал до "
          "линии не доходит:")
    print("проверьте перемычку TX-RX (--loopback), полярность A/B и общий "
          "провод (GND) с платой.")
    return 1


def run_rs485_probe(args) -> int:
    """Проверяет, отвечает ли плата на наш собственный запрос по шине.

    Пока мы шину только слушали. Прежде чем пытаться ею управлять, надо
    выяснить простую вещь: слышит ли нас плата вообще. Проба это выясняет,
    ничего не меняя — по умолчанию отправляется точная копия того запроса,
    который мастер и так шлёт двадцать раз в минуту (``CMD=0x55``,
    нагрузка ``00 00 11``), только от чужого, никем не занятого адреса.

    Признаком успеха служит **новизна** кадра, а не его адрес. Судить по
    адресу нельзя: у мастера ``F1`` он стоит почти в каждом кадре штатного
    цикла, и такой фильтр объявляет удачей обычную переписку — на живом
    железе именно это и произошло. Поэтому проба сперва слушает линию и
    запоминает, из чего цикл состоит, а засчитывает только то, чего в цикле
    не было: например ответ на пять регистров там, где мастер всегда просит
    семнадцать.

    Кадр отправляется в паузе между пачками мастера (:data:`PROBE_IDLE`),
    иначе он наложится на чужую посылку и пропадёт вместе с ней.
    """
    from aux_hvac.rs485_protocol import RS485Decoder, RS485Frame

    transport = RS485Transport(
        port=args.port,
        baudrate=args.baud,
        parity=args.parity,
        timeout=args.read_timeout,
        address=args.address,
    )

    try:
        payload = bytes.fromhex(args.probe_payload.replace(" ", ""))
    except ValueError:
        print("Нагрузка --probe-payload должна быть шестнадцатеричной, "
              "получено %r" % args.probe_payload, file=sys.stderr)
        return 2

    # собираем и тут же разбираем обратно: так describe() покажет настоящую
    # длину и сошедшуюся CRC, а не поля пустой заготовки
    raw = RS485Frame(addr_a=args.probe_from, addr_b=args.probe_to,
                     cmd=args.probe_cmd, payload=payload).encode()
    frame = RS485Frame.decode(raw)

    print("RS485: проба передачи. Ничего не меняем — это запрос на чтение.")
    print("Параметры: %r" % transport)
    print("Отправляем %d раз: %s" % (args.probe_tries, frame.describe()))
    print("  байты: %s" % " ".join("%02X" % b for b in raw))
    print("Ждём ответ, адресованный %02X.\n" % args.probe_from)

    try:
        transport.open()
    except TransportError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        return 2

    decoder = RS485Decoder()
    dump = open(args.dump, "ab") if args.dump else None
    answers, echoes = [], 0
    baseline = set()
    echo_meaningful = True
    quiet_bad = busy_bad = 0
    # ответы опрашиваемого до пробы и во время неё: если плата нас слышит,
    # лишние опросы дадут лишние ответы — и это видно даже тогда, когда сам
    # ответ от штатного не отличается
    without_us = with_us = sends = 0

    def signature(f):
        """Чем один кадр цикла отличается от другого.

        Значения регистров сюда не входят: температуры плывут сами по себе,
        и по ним любой кадр выглядел бы новым. А вот адреса, команда, длина
        и начало нагрузки — индекс с количеством — от опроса к опросу
        повторяются в точности.
        """
        return (f.addr_a, f.addr_b, f.cmd, len(f.payload), bytes(f.payload[:2]))

    seen_here = []      # кадры, замеченные последним wait_idle()

    def drain(seconds):
        """Читает линию заданное время, возвращает разобранные кадры."""
        got = []
        end = time.monotonic() + seconds
        while time.monotonic() < end and not _stop:
            chunk = transport.read(256)
            if not chunk:
                time.sleep(0.002)
                continue
            if dump is not None:
                dump.write(chunk)
            got.extend(decoder.feed(chunk))
        return got

    def wait_idle(limit=3.0):
        """Ждёт паузу в линии. Возвращает False, если так и не дождались.

        Кадры, попавшиеся за время ожидания, возвращаются наружу через
        ``seen_here``: их обязательно надо посчитать, иначе замер частоты
        сравнивает несравнимое — непрерывное наблюдение в одной фазе с
        наблюдением по окнам в другой.
        """
        del seen_here[:]
        end = time.monotonic() + limit
        quiet = time.monotonic()
        while time.monotonic() < end and not _stop:
            chunk = transport.read(256)
            if chunk:
                if dump is not None:
                    dump.write(chunk)
                seen_here.extend(decoder.feed(chunk))
                quiet = time.monotonic()
                continue
            if time.monotonic() - quiet >= PROBE_IDLE:
                return True
            time.sleep(0.002)
        return False

    try:
        print("Слушаем линию и запоминаем штатный цикл...")
        before = drain(args.probe_learn)
        baseline = {signature(f) for f in before}
        # эхо опознаётся только по совпадению байтов, поэтому оно бессмысленно,
        # когда точно такой же кадр шлёт кто-то ещё: чужая посылка тогда
        # неотличима от нашей собственной
        echo_meaningful = all(f.raw != raw for f in before)
        without_us = sum(1 for f in before if f.addr_a == args.probe_to)
        quiet_bad = decoder.bad_crc
        if before:
            print("За %.0f с принято кадров: %d, из них разных: %d. Шина живая."
                  % (args.probe_learn, len(before), len(baseline)))
        else:
            print("Ни одного кадра не принято — проверьте линию и скорость.")
        if args.probe_from in {a for f in before for a in (f.addr_a, f.addr_b)}:
            print("Замечание: адрес %02X на шине уже занят. Ответ на наш кадр"
                  % args.probe_from)
            print("отличим только по содержимому — запрашивайте заведомо")
            print("непривычное: другое количество регистров или другой индекс.")
        print("")

        started = time.monotonic()
        span = 0.0
        bad_at_start = decoder.bad_crc
        for attempt in range(1, args.probe_tries + 1):
            if _stop:
                break
            idle = wait_idle()
            with_us += sum(1 for f in seen_here if f.addr_a == args.probe_to)
            if not idle:
                print("%d: паузы в линии не нашлось, пропускаем попытку"
                      % attempt)
                continue
            transport.write(raw)
            sends += 1
            replies = drain(args.probe_wait)
            fresh = []
            for f in replies:
                if f.raw == raw and echo_meaningful:
                    echoes += 1       # адаптер вернул нам нашу же передачу
                    continue
                if f.addr_a == args.probe_to:
                    with_us += 1
                if signature(f) not in baseline:
                    fresh.append(f)
            if fresh:
                answers.extend(fresh)
                for f in fresh:
                    print("%d: НОВЫЙ КАДР  %s" % (attempt, f.describe()))
                    # запоминаем, иначе один и тот же ответ будет считаться
                    # новым на каждой попытке и создаст видимость находки
                    baseline.add(signature(f))
            else:
                print("%d: ничего нового (кадров штатного цикла за это время: %d)"
                      % (attempt, len(replies)))
        span = time.monotonic() - started
        busy_bad = decoder.bad_crc - bad_at_start
    except TransportError as exc:
        print("Ошибка линии: %s" % exc, file=sys.stderr)
        return 2
    finally:
        decoder.flush()
        transport.close()
        if dump is not None:
            dump.close()

    print("")
    quiet_rate = without_us / args.probe_learn if args.probe_learn else 0.0
    busy_rate = with_us / span if span else 0.0
    print("Ответов от %02X без нас: %d за %.1f с = %.2f/с"
          % (args.probe_to, without_us, args.probe_learn, quiet_rate))
    print("Ответов от %02X с нами : %d за %.1f с = %.2f/с "
          "(отправлено запросов: %d)"
          % (args.probe_to, with_us, span, busy_rate, sends))
    print("Битых CRC: без нас %d, с нами %d" % (quiet_bad, busy_bad))
    if busy_bad > quiet_bad + sends // 4:
        print("Наши кадры накладываются на чужие — замер частоты этим "
              "испорчен.")
        print("Увеличьте --probe-wait, чтобы реже влезать в чужую посылку.")
    faster = quiet_rate > 0 and busy_rate >= quiet_rate * PROBE_RATE_FACTOR
    if faster:
        print("Ответы участились — плата отвечает на наши запросы.")
    print("")

    if not echo_meaningful:
        print("Эхо не проверялось: такой же кадр шлёт мастер, и его посылку "
              "от нашей")
        print("не отличить. Чтобы проверить передатчик, возьмите адрес, "
              "которого на")
        print("шине нет: --probe-from B1.")
    elif echoes:
        print("Эхо: %d раз наш кадр вернулся в приёмник целиком и со "
              "сошедшейся CRC." % echoes)
        print("Приёмник адаптера слушает саму линию — значит линия была нами "
              "проведена")
        print("и кадр в шине действительно был. За ответ такие кадры, "
              "разумеется, не")
        print("считались.")
    else:
        print("Эха нет. Многие адаптеры его глушат, так что само по себе это "
              "ещё не")
        print("приговор передатчику — но и подтверждения передачи у нас нет. "
              "Проверить")
        print("однозначно: --probe-collide.")
    if echoes and not faster and not answers:
        print("Передатчик работает, но плата на этот кадр не отвечает.")
        return 1

    if faster and not answers:
        print("Плата нас слышит: своих кадров она не показала, но отвечать "
              "стала чаще ровно тогда, когда мы начали спрашивать.")
        print("Значит передача работает, а нагрузка запроса на форму ответа "
              "не влияет — количество регистров плата берёт своё.")
        return 0

    if answers:
        print("Плата нас слышит: %d кадров, каких в штатном цикле не бывает."
              % len(answers))
        print("Значит передача работает и плата приняла именно наш запрос. "
              "Дальше имеет смысл искать команду записи.")
        return 0

    print("Плата на наш запрос не отвечает. Причин три, и различать их надо "
          "по порядку:")
    print("  1. передатчик до шины не доходит — проверяется --probe-collide;")
    print("  2. плата отвечает не всякому: попробуйте --probe-from C1, C2, "
          "CF, E1;")
    print("  3. ответ платы вообще не вызван запросом, а идёт по её "
          "собственному")
    print("     расписанию — тогда управлять чтением её не заставить.")
    return 1


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
    # ВАЖНО: значение по умолчанию именно None. Раньше здесь стояло 4800, а
    # режим --rs485 отличал «пользователь не указал скорость» сравнением
    # args.baud с 4800 — и потому молча съедал явное --baud 4800. Теперь
    # умолчание подставляет сам режим, см. _apply_line_defaults().
    parser.add_argument("-b", "--baud", type=int, default=None,
                        help="скорость (по умолчанию %d, для --rs485 %d)"
                             % (UART_BAUDRATE, RS485_BAUDRATE))
    parser.add_argument(
        "--parity",
        default=None,
        choices=["N", "E", "O", "M", "S"],
        help="чётность (по умолчанию E, как требует протокол AUX; "
             "для --rs485 N)",
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
    one.add_argument("--timer", metavar="Ч:ММ",
                     help="таймер: задержка вида 2:30 либо off. off сбрасывает и "
                          "задержку, и бит TMR, и нерасшифрованный бит 7 байта 18, "
                          "иначе индикатор таймера может остаться горящим")
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
    rs.add_argument("--correlate", action="store_true",
                    help="слушать UART и RS485 одновременно и сопоставлять "
                         "регистры шины с расшифрованными полями UART")
    rs.add_argument("--rs485-port", metavar="ПОРТ",
                    help="порт шины RS485 для --correlate, например COM9")
    rs.add_argument("--sweep", action="store_true",
                    help="активный проход: менять величины по UART по одной и "
                         "смотреть, какие регистры шины на это отвечают")
    rs.add_argument("--sweep-settle", type=float, default=SWEEP_SETTLE,
                    help="сколько секунд слушать шину после каждого шага "
                         "прохода (по умолчанию %.0f). Отдельный флаг от "
                         "--settle: тот про паузу перед чтением результата "
                         "одиночной команды" % SWEEP_SETTLE)
    rs.add_argument("--correlate-interval", type=float,
                    default=CORRELATE_POLL_INTERVAL,
                    help="период запроса статусов при сопоставлении, с "
                         "(по умолчанию %.1f, что даёт 7 с на каждый вид "
                         "статуса — как в эталонной реализации)"
                         % CORRELATE_POLL_INTERVAL)
    rs.add_argument("--rs485-probe", action="store_true",
                    help="проба передачи в шину: отправить свой запрос на "
                         "чтение и посмотреть, ответит ли плата. Ничего не "
                         "меняет")
    rs.add_argument("--probe-collide", type=float, metavar="СЕК",
                    help="проверка передатчика столкновением: слать мусор "
                         "поверх чужих передач заданное число секунд и "
                         "смотреть, портится ли их CRC. Не зависит от того, "
                         "слышит ли нас плата")
    rs.add_argument("--probe-from", type=lambda s: int(s, 0), default=0xB1,
                    metavar="АДР",
                    help="каким адресом представиться (по умолчанию 0xB1 — "
                         "он на шине не занят, так ответ нам не спутать с "
                         "чужим)")
    rs.add_argument("--probe-to", type=lambda s: int(s, 0), default=0x01,
                    metavar="АДР",
                    help="кого спрашиваем (по умолчанию 0x01 — плата, "
                         "которая отдаёт датчики)")
    rs.add_argument("--probe-cmd", type=lambda s: int(s, 0), default=0x55,
                    metavar="КОМ",
                    help="команда (по умолчанию 0x55 — чтение блока)")
    rs.add_argument("--probe-payload", default="000011", metavar="HEX",
                    help="нагрузка (по умолчанию 000011 — ровно то, что "
                         "шлёт мастер)")
    rs.add_argument("--probe-learn", type=float, default=5.0, metavar="СЕК",
                    help="сколько секунд слушать штатный цикл перед пробой, "
                         "чтобы потом отличить от него ответ (по умолчанию 5)")
    rs.add_argument("--probe-wait", type=float, default=PROBE_WAIT,
                    metavar="СЕК",
                    help="сколько слушать после своего кадра (по умолчанию "
                         "%.1f). Малое значение вместе с большим "
                         "--probe-tries даёт частый опрос: так проверяется, "
                         "вызван ли ответ платы вообще запросом"
                         % PROBE_WAIT)
    rs.add_argument("--probe-tries", type=int, default=5, metavar="N",
                    help="сколько раз повторить (по умолчанию 5)")
    rs.add_argument("--sniff-raw", action="store_true", help="синоним --rs485 для наглядности")
    rs.add_argument("--address", type=lambda s: int(s, 0), default=0x01, help="адрес устройства на шине")

    return parser


def _apply_line_defaults(args) -> None:
    """Подставляет параметры линии по умолчанию для выбранного интерфейса.

    Умолчания разные: интерфейс wifi-модуля работает на 4800/8-E-1 (так
    требует протокол AUX), а шина RS485 — на 9600/8-N-1. Поэтому argparse
    оставляет здесь None, а конкретное значение выбирается уже по режиму.
    """
    rs485 = args.rs485 or args.sniff_raw or args.rs485_probe or args.probe_collide
    if args.baud is None:
        args.baud = RS485_BAUDRATE if rs485 else UART_BAUDRATE
    if args.parity is None:
        args.parity = RS485_PARITY if rs485 else UART_PARITY


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    _apply_line_defaults(args)

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
        # --sweep и --correlate раньше --rs485: им нужны оба интерфейса сразу
        if args.sweep:
            return run_sweep(args)
        if args.correlate:
            return run_correlate(args)
        # --rs485 проверяем раньше --monitor: у шины своя панель, и общий
        # монитор к ней не подходит — там нет ни опроса, ни статуса блока
        # проба раньше прослушивания: --rs485-probe подразумевает шину, но
        # слушать вместо передачи было бы не тем, о чём просили
        if args.probe_collide:
            return run_rs485_probe_collide(args)
        if args.rs485_probe:
            return run_rs485_probe(args)
        if args.rs485 or args.sniff_raw:
            return run_rs485(args)
        if args.monitor:
            return run_monitor(args)
        if args.watch:
            return run_watch(args)
        if args.status or args.set_mode_flag:
            return run_command(args)
        if args.loopback:
            return run_loopback(args)
        return run_aux(args)
    except ValueError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
