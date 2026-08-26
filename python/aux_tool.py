#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Инструмент проверки протокола AUX. Работает офлайн, железо не нужно.

Нужен для того, чтобы проверять кодек и разбирать дампы, не подключаясь к
кондиционеру. Все подкоманды детерминированы и возвращают осмысленный код
возврата, так что их удобно дёргать из скриптов и CI.

Подкоманды::

    selftest             прогон всех примеров пакетов из README
    crc BB 00 01 ...     контрольная сумма для набора байт
    decode BB 00 07 ...  разбор кадра (или нескольких подряд)
    encode ping          сборка известных пакетов
    replay dump.log      разбор записанного дампа линии
    ports                список доступных COM-портов

Примеры::

    python aux_tool.py selftest
    python aux_tool.py decode "BB 00 07 00 00 00 18 00 01 21 C0 3D 00 02 54 3A 00 29 00 00 00 00 00 00 00 00 00 00 00 00 00 05 10 36"
    python aux_tool.py encode control --temp 22 --mode cool --power on
    python aux_tool.py replay dump.log --json
"""

from __future__ import annotations

import argparse
import binascii
import json
import re
import sys
from typing import List, Optional

sys.path.insert(0, __file__.rsplit("aux_tool.py", 1)[0] or ".")

# Консоль Windows по умолчанию не в UTF-8, а весь вывод здесь русскоязычный.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):  # pragma: no cover - старый Python или не-TTY
        pass

from aux_hvac import (  # noqa: E402
    Command,
    FanSpeed,
    IndoorState,
    Mode,
    OutdoorState,
    Packet,
    PacketError,
    StreamDecoder,
    VerticalLouver,
    byte_names,
    control,
    crc16_bytes,
    decode_state,
    hexdump,
    init_response,
    ping_request,
    ping_response,
    request_indoor,
    request_outdoor,
    unknown_0b,
)

# ===========================================================================
#  Эталонные примеры из README
# ===========================================================================

#: (описание, кадр целиком в hex). Все значения взяты из таблиц README.
README_PACKETS = [
    ("TYPE=0x01 ping от сплита", "BB 00 01 00 00 00 00 00 43 FF"),
    ("TYPE=0x01 ответ модуля", "BB 00 01 80 01 00 08 00 1C 27 00 00 00 00 00 00 1E 58"),
    ("TYPE=0x06 CMD=0x21 запрос внешнего блока", "BB 00 06 80 00 00 02 00 21 01 1B 7E"),
    ("TYPE=0x06 CMD=0x11 запрос внутреннего блока", "BB 00 06 80 00 00 02 00 11 01 2B 7E"),
    (
        "TYPE=0x06 CMD=0x01 команда управления",
        "BB 00 06 80 00 00 0F 00 01 01 97 00 02 60 00 20 00 00 00 00 00 00 00 94 FD",
    ),
    (
        "TYPE=0x07 CMD=0x21 статус внешнего блока",
        "BB 00 07 00 00 00 18 00 01 21 C0 3D 00 02 54 3A 00 29 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 05 10 36",
    ),
    (
        "TYPE=0x06 CMD=0x01 попытка включить iFeel (лог README)",
        "BB 00 06 80 00 00 0F 00 01 01 97 20 00 40 00 20 00 00 20 00 10 00 00 66 FD",
    ),
    (
        "TYPE=0x07 CMD=0x11 ответ на неё (лог README)",
        "BB 00 07 00 00 00 0F 00 01 11 97 20 00 40 00 28 00 00 20 00 10 00 00 66 65",
    ),
    ("TYPE=0x09 инициирование от сплита", "BB 00 09 00 00 00 01 00 02 38 FF"),
    ("TYPE=0x09 ответ модуля", "BB 00 09 80 01 00 00 00 3A 7F"),
    ("TYPE=0x0B вар.1", "BB 00 0B 80 00 00 02 00 00 00 37 7F"),
    ("TYPE=0x0B вар.2", "BB 00 0B 80 00 00 02 00 01 00 36 7F"),
    ("TYPE=0x0B вар.3", "BB 00 0B 80 00 00 02 00 02 00 35 7F"),
    ("TYPE=0x0B вар.4", "BB 00 0B 80 00 00 02 00 03 00 34 7F"),
]


class Checker:
    """Простой накопитель результатов проверок."""

    def __init__(self, verbose: bool = True) -> None:
        self.passed = 0
        self.failed: List[str] = []
        self.verbose = verbose

    def check(self, title: str, got, expected) -> bool:
        ok = got == expected
        if ok:
            self.passed += 1
            if self.verbose:
                print("  ok   %s" % title)
        else:
            self.failed.append(title)
            print("  FAIL %s\n         получено: %r\n         ожидалось: %r" % (title, got, expected))
        return ok

    def check_true(self, title: str, value) -> bool:
        return self.check(title, bool(value), True)

    def report(self) -> int:
        total = self.passed + len(self.failed)
        if self.failed:
            print("\nПРОВАЛЕНО %d из %d:" % (len(self.failed), total))
            for name in self.failed:
                print("  - %s" % name)
            return 1
        print("\nВсе проверки пройдены: %d из %d." % (self.passed, total))
        return 0


# ===========================================================================
#  selftest
# ===========================================================================

def cmd_selftest(args) -> int:
    c = Checker(verbose=not args.quiet)

    print("1. CRC и сборка/разбор кадров из README")
    for title, hexstr in README_PACKETS:
        frame = _parse_hex(hexstr)
        # CRC совпадает с указанной в README
        c.check("CRC %s" % title, crc16_bytes(frame[:-2]), frame[-2:])
        # кадр разбирается и пересобирается байт в байт
        try:
            packet = Packet.decode(frame)
        except PacketError as exc:
            c.check("разбор %s" % title, str(exc), "без ошибок")
            continue
        c.check("round-trip %s" % title, packet.encode(), frame)

    print("\n2. Конструкторы известных пакетов")
    c.check("ping от сплита", ping_request().encode(), _parse_hex("BB 00 01 00 00 00 00 00 43 FF"))
    c.check(
        "ответ модуля на ping",
        ping_response().encode(),
        _parse_hex("BB 00 01 80 01 00 08 00 1C 27 00 00 00 00 00 00 1E 58"),
    )
    c.check("запрос внутреннего блока", request_indoor().encode(), _parse_hex("BB 00 06 80 00 00 02 00 11 01 2B 7E"))
    c.check("запрос внешнего блока", request_outdoor().encode(), _parse_hex("BB 00 06 80 00 00 02 00 21 01 1B 7E"))
    c.check("ответ модуля на инициирование", init_response().encode(), _parse_hex("BB 00 09 80 01 00 00 00 3A 7F"))
    for i, expected in enumerate(("37 7F", "36 7F", "35 7F", "34 7F")):
        c.check("пакет 0x0B, счётчик %d" % i, unknown_0b(i).encode()[-2:], _parse_hex(expected))

    print("\n3. Разбор статуса внешнего блока (пример из README, CMD=0x21)")
    packet = Packet.decode(_parse_hex(README_PACKETS[5][1]))
    st = decode_state(packet)
    c.check_true("тип состояния — OutdoorState", isinstance(st, OutdoorState))
    # CONF=0xC0 -> обычный on-off сплит; MODE=0x3D -> 0011 1101
    c.check("не инвертор (CONF=0xC0)", st.inverter, False)
    c.check("стационарный (бит 7 CONF)", st.stationary, True)
    c.check("не дежурный пакет", st.periodic, False)
    c.check("питание включено (бит PWR байта 11)", st.power, True)
    c.check("режим COOL (биты MD байта 11)", st.mode, Mode.COOL)
    c.check("жалюзи включены (бит LON)", st.louvers_on, True)
    c.check("горизонтальные жалюзи (бит HL)", st.horizontal_louver, True)
    c.check("вертикальные жалюзи (бит VL)", st.vertical_louver, True)
    c.check("нет сна (бит SLP)", st.sleep, False)
    c.check("нет разморозки (байт 12 = 0x00)", st.defrost, False)
    # Tint=0x3A, Tid=0x05 -> 0x3A-0x20 + 0.5 = 26 + 0.5
    c.check("температура в комнате 26.5 °C", round(st.indoor_temp, 1), 26.5)
    c.check("десятые доли градуса", st.temp_fraction, 5)
    c.check("датчика уличной температуры нет (байт 20 = 0x00)", st.outdoor_temp, None)
    c.check("температуры компрессора нет (байт 22 = 0x00)", st.compressor_temp, None)
    c.check("мощность инвертора 0 %", st.inverter_power, 0)
    c.check("ошибок нет (байт 29 = 0x00)", st.error_code, 0)
    c.check("фактическая скорость вентилятора LOW", int(st.real_fan_speed), 0x02)
    c.check("ШИМ вентилятора 0x54", st.fan_pwm, 0x54)

    print("\n4. Разбор статуса внутреннего блока (лог iFeel из README)")
    packet = Packet.decode(_parse_hex(README_PACKETS[7][1]))
    st = decode_state(packet)
    c.check_true("тип состояния — IndoorState", isinstance(st, IndoorState))
    # TS=0x97 -> 1001 0111: целая часть 0x97>>3 = 18, шторки 0b111 = STOP
    c.check("целевая температура 26 °C", st.target_temp, 26.0)
    c.check("вертикальные шторки остановлены", st.vertical_louver, VerticalLouver.STOP)
    c.check("качание влево-вправо выключено (SL=0x20)", st.swing_lr, False)
    c.check("скорость вентилятора MEDIUM (байт 13 = 0x40)", st.fan_speed, FanSpeed.MEDIUM)
    c.check("режим COOL (MO=0x28)", st.mode, Mode.COOL)
    c.check("iFeel включён (бит iFL байта 15)", st.ifeel, True)
    c.check("питание включено (EN=0x20)", st.power, True)
    c.check("дисплей включён (FL=0x10)", st.display, True)
    c.check("антиплесень выключена", st.mildew, False)
    c.check("турбо выключено", st.turbo, False)
    c.check("ограничение мощности снято", st.power_limit_enabled, False)

    print("\n5. Сборка команды управления из статуса")
    # README, «Последовательности команд»: модуль берёт тело статуса 0x11,
    # правит нужные биты и отправляет его же командой 0x01.
    src = Packet.decode(_parse_hex(README_PACKETS[7][1]))
    state = decode_state(src)
    expected_cmd = _parse_hex(README_PACKETS[6][1])
    # у команды из README сброшен только бит iFL (0x28 -> 0x20)
    state.payload[5] &= ~0x08 & 0xFF
    c.check("команда собирается байт в байт как в логе README", state.to_command().encode(), expected_cmd)

    print("\n6. Мутаторы состояния")
    st = IndoorState(payload=bytearray(13))
    c.check("температура 22.0 °C", st.set_target_temp(22).target_temp, 22.0)
    c.check("температура 23.5 °C", st.set_target_temp(23.5).target_temp, 23.5)
    c.check("бит TD выставлен для половины градуса", st.half_degree, True)
    c.check("температура 24.0 °C сбрасывает бит TD", st.set_target_temp(24).half_degree, False)
    c.check("режим HEAT", st.set_mode(Mode.HEAT).mode, Mode.HEAT)
    c.check("режим FAN", st.set_mode(Mode.FAN).mode, Mode.FAN)
    c.check("вентилятор AUTO", st.set_fan_speed(FanSpeed.AUTO).fan_speed, FanSpeed.AUTO)
    c.check("вентилятор MEDIUM", st.set_fan_speed(FanSpeed.MEDIUM).fan_speed, FanSpeed.MEDIUM)
    c.check("включение", st.set_power(True).power, True)
    c.check("выключение", st.set_power(False).power, False)
    c.check("турбо вкл", st.set_turbo(True).turbo, True)
    c.check("тихий режим вкл", st.set_mute(True).mute, True)
    c.check("турбо и тихий не мешают друг другу", (st.turbo, st.mute), (True, True))
    c.check("шторки в среднее положение", st.set_vertical_louver(VerticalLouver.MIDDLE).vertical_louver, VerticalLouver.MIDDLE)
    c.check("температура пережила смену шторок", st.target_temp, 24.0)
    c.check("качание LR вкл", st.set_swing_lr(True).swing_lr, True)
    c.check("качание LR выкл", st.set_swing_lr(False).swing_lr, False)
    c.check("лимит мощности 47 %", st.set_power_limit(47).power_limit, 47)
    c.check("лимит мощности включён", st.power_limit_enabled, True)
    c.check("лимит 100 % даёт байт 0xE4 (README)", st.set_power_limit(100).raw_pwr_lim, 0xE4)
    c.check("снятие лимита оставляет 0x64 (README)", st.set_power_limit(None).raw_pwr_lim, 0x64)
    c.check("таймер 5 ч 30 мин", (st.set_timer(5, 30).timer_hours, st.timer_minutes), (5, 30))
    c.check("флаг таймера поднят", st.timer_enabled, True)
    c.check("режим HEALTH", st.set_health(True).health, True)
    c.check("байт EN при HEALTH равен 0x22 (README)", st.set_power(True).set_health(True).raw_en & 0x62, 0x62)
    c.check("iCLEAN выставляет байт 18 в 0x04 (README)", st.set_clean(True).raw_en, 0x04)
    c.check("длина тела команды 13 байт", len(st.payload), 13)

    print("\n7. Потоковый разборщик")
    stream = b"".join(Packet.decode(_parse_hex(h)).encode() for _, h in README_PACKETS)
    dec = StreamDecoder()
    got = []
    for i in range(0, len(stream), 3):  # рвём поток на мелкие куски
        got.extend(dec.feed(stream[i:i + 3]))
    c.check("разобраны все кадры подряд", len(got), len(README_PACKETS))
    c.check("мусора не обнаружено", dec.dropped_bytes, 0)
    c.check("кадры совпали байт в байт", [p.raw for p in got], [_parse_hex(h) for _, h in README_PACKETS])

    dec = StreamDecoder()
    got = dec.feed(b"\x00\xff\x12" + stream)
    c.check("пересинхронизация после мусора", len(got), len(README_PACKETS))
    c.check("мусорные байты посчитаны", dec.dropped_bytes, 3)

    # битый ping: потерян старший байт CRC, следом сразу идёт другой кадр
    broken = _parse_hex("BB 00 01 80 01 00 08 00 1C 27 00 00 00 00 00 00 1E")
    dec = StreamDecoder()
    got = dec.feed(broken + _parse_hex(README_PACKETS[5][1]))
    c.check("битый и следующий за ним кадр разобраны", len(got), 2)
    if len(got) == 2:
        c.check("первый помечен как обрезанный", got[0].truncated, True)
        c.check("второй разобран нормально", got[1].crc_ok, True)

    # Royal Clima: лишний нулевой байт в конце тела, не учтённый в LEN
    body = _parse_hex(README_PACKETS[5][1])[:-2] + b"\x00"
    royal = body + crc16_bytes(body)
    dec = StreamDecoder()
    got = dec.feed(royal)
    c.check("кадр Royal Clima на 35 байт разобран", len(got), 1)
    if got:
        c.check("тело Royal Clima на байт длиннее", len(got[0].body), 25)
        c.check("состояние Royal Clima разбирается", isinstance(decode_state(got[0]), OutdoorState), True)

    print("\n8. Устойчивость к некорректным данным")
    c.check("кадр с испорченной CRC отвергается", _decode_fails("BB 00 01 00 00 00 00 00 43 FE"), True)
    c.check("кадр без стартового байта отвергается", _decode_fails("AA 00 01 00 00 00 00 00 43 FF"), True)
    c.check("слишком короткий кадр отвергается", _decode_fails("BB 00 01"), True)
    c.check("несовпадение LEN и длины отвергается", _decode_fails("BB 00 01 00 00 00 05 00 43 FF"), True)
    try:
        control(b"\x00" * 12)
        short_body_rejected = False
    except PacketError:
        short_body_rejected = True
    c.check("команда управления с телом не в 13 байт отвергается", short_body_rejected, True)

    print("\n9. Клиент поверх транспорта-заглушки")
    from aux_hvac import LoopbackTransport, AuxClient

    link = LoopbackTransport()
    client = AuxClient(link, active=True, poll_interval=1e9)  # опрос по таймеру отключаем
    client.open()
    # сплит шлёт ping, инициирование и статус внешнего блока
    link.inject(_parse_hex(README_PACKETS[0][1]))
    link.inject(_parse_hex(README_PACKETS[8][1]))
    link.inject(_parse_hex(README_PACKETS[5][1]))
    seen = []
    while True:
        batch = client.poll_once()
        if not batch:
            break
        seen.extend(batch)
    c.check("клиент разобрал все три кадра", len(seen), 3)
    c.check(
        "ответил на ping и на инициирование",
        bytes(link.sent),
        ping_response().encode() + init_response().encode(),
    )
    c.check("ответов на ping посчитано", client.stats.pings_answered, 1)
    c.check_true("статус внешнего блока сохранён", isinstance(client.outdoor, OutdoorState))
    c.check("статуса внутреннего блока ещё не было", client.indoor, None)

    # пассивный клиент не должен ничего передавать
    link = LoopbackTransport(rx=_parse_hex(README_PACKETS[0][1]))
    passive = AuxClient(link, active=False)
    passive.open()
    passive.poll_once()
    c.check("пассивный режим молчит", bytes(link.sent), b"")

    # явный запрос и отправка команды
    link = LoopbackTransport()
    client = AuxClient(link, active=True)
    client.open()
    client.request(Command.INDOOR)
    client.request(Command.OUTDOOR)
    client.apply(IndoorState(payload=bytearray(13)).set_power(True).set_mode(Mode.HEAT).set_target_temp(21))
    c.check(
        "запросы ушли в линию как в README",
        bytes(link.sent)[:24],
        request_indoor().encode() + request_outdoor().encode(),
    )
    sent_cmd = Packet.decode(bytes(link.sent)[24:])
    c.check("команда управления имеет CMD=0x01", sent_cmd.cmd, Command.CONTROL)
    applied = decode_state(sent_cmd)
    c.check("в команде включение", applied.power, True)
    c.check("в команде режим HEAT", applied.mode, Mode.HEAT)
    c.check("в команде 21 °C", applied.target_temp, 21.0)

    return c.report()


def _decode_fails(hexstr: str) -> bool:
    try:
        Packet.decode(_parse_hex(hexstr))
        return False
    except PacketError:
        return True


# ===========================================================================
#  Вспомогательное
# ===========================================================================

def _parse_hex(text) -> bytes:
    """Терпимо разбирает hex: пробелы, 0x, запятые, скобки и метки направления."""
    if isinstance(text, (list, tuple)):
        text = " ".join(text)
    text = re.sub(r"\[(?:=>|<=)\]", " ", text)
    text = re.sub(r"0[xX]", "", text)
    cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(cleaned) % 2:
        raise ValueError("нечётное количество hex-символов: %r" % text)
    return binascii.unhexlify(cleaned)


def _parse_hex_log(text: str) -> bytes:
    """Разбирает текстовый лог линии.

    В отличие от :func:`_parse_hex`, не склеивает подряд все hex-символы, а
    берёт только отдельные двухсимвольные токены. Иначе латинские буквы из
    комментариев (README, CRC, aux_ac) попадали бы в поток как данные.
    Строки после ``#`` игнорируются целиком.
    """
    out = bytearray()
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        line = re.sub(r"\[(?:=>|<=)\]", " ", line)
        for token in re.findall(r"(?<![0-9a-zA-Z])([0-9a-fA-F]{2})(?![0-9a-zA-Z])", line):
            out.append(int(token, 16))
    return bytes(out)


def _packet_report(packet: Packet, as_json: bool = False, show_bits: bool = False) -> str:
    state = None
    if packet.crc_ok:
        try:
            state = decode_state(packet)
        except ValueError:
            state = None

    if as_json:
        data = {
            "raw": hexdump(packet.raw or packet.encode()),
            "type": "0x%02X" % packet.ptype,
            "direction": "module" if packet.from_module else "ac",
            "cmd": None if packet.cmd is None else "0x%02X" % packet.cmd,
            "body_len": len(packet.body),
            "crc_ok": packet.crc_ok,
            "truncated": packet.truncated,
            "state": state.to_dict() if state is not None else None,
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    lines = [packet.describe()]
    if state is not None:
        lines.append("      " + state.describe())
        for key, value in state.to_dict().items():
            if key == "unknown":
                continue
            lines.append("        %-22s %s" % (key, value))
        unknown = state.to_dict().get("unknown") or {}
        if unknown:
            lines.append(
                "        %-22s %s"
                % ("нерасшифровано", ", ".join("%s=0x%02X" % kv for kv in sorted(unknown.items())))
            )
    if show_bits:
        raw = packet.raw or packet.encode()
        names = byte_names(packet)
        crc_at = len(raw) - 2
        lines.append("      побайтно (имена байтов — по нумерации README):")
        for i, byte in enumerate(raw):
            if i >= crc_at:
                name = "CRC%d" % (i - crc_at + 1)
            else:
                name = names.get(i, "")
            lines.append(
                "        [%2d] %-9s 0x%02X  %s  %3d"
                % (i, name, byte, format(byte, "08b"), byte)
            )
    return "\n".join(lines)


# ===========================================================================
#  Подкоманды
# ===========================================================================

def cmd_crc(args) -> int:
    data = _parse_hex(args.data)
    crc = crc16_bytes(data)
    print("данные: %s" % hexdump(data))
    print("CRC:    %s   (CRC1=0x%02X, CRC2=0x%02X)" % (hexdump(crc), crc[0], crc[1]))
    print("кадр:   %s" % hexdump(data + crc))
    return 0


def cmd_decode(args) -> int:
    data = _parse_hex(args.data)
    dec = StreamDecoder()
    packets = dec.feed(data)
    if not packets:
        print("Кадры не найдены. Данных %d байт, отброшено %d." % (len(data), dec.dropped_bytes))
        return 1
    for packet in packets:
        print(_packet_report(packet, as_json=args.json, show_bits=args.bits))
    if dec.dropped_bytes:
        print("\nотброшено мусорных байт: %d" % dec.dropped_bytes)
    return 0 if all(p.crc_ok for p in packets) else 1


_MODES = {m.name.lower(): m for m in Mode}
_FANS = {f.name.lower(): f for f in FanSpeed}
_LOUVERS = {v.name.lower(): v for v in VerticalLouver}


def cmd_encode(args) -> int:
    if args.what == "ping":
        packet = ping_response() if args.module else ping_request()
    elif args.what == "ping-request":
        packet = ping_request()
    elif args.what == "indoor":
        packet = request_indoor(args.seq)
    elif args.what == "outdoor":
        packet = request_outdoor(args.seq)
    elif args.what == "init":
        packet = init_response()
    elif args.what == "0b":
        packet = unknown_0b(args.counter)
    elif args.what == "control":
        packet = _build_control(args)
    else:  # pragma: no cover - argparse не пропустит
        raise ValueError(args.what)

    raw = packet.encode()
    if args.raw:
        sys.stdout.write(hexdump(raw, sep="") + "\n")
        return 0
    print(_packet_report(Packet.decode(raw), as_json=args.json, show_bits=args.bits))
    return 0


def _build_control(args) -> Packet:
    """Собирает команду управления из базового состояния и ключей CLI."""
    if args.base:
        base = _parse_hex(args.base)
        if len(base) >= 10:
            # передали кадр целиком — вытаскиваем из него состояние
            state = decode_state(Packet.decode(base, strict=False))
            if not isinstance(state, IndoorState):
                raise ValueError("в базовом кадре нет статуса внутреннего блока")
        elif len(base) == 13:
            state = IndoorState(payload=bytearray(base))
        else:
            raise ValueError("--base ожидает 13 байт тела либо кадр целиком")
    else:
        state = IndoorState(payload=bytearray(13))

    if args.power is not None:
        state.set_power(args.power == "on")
    if args.mode is not None:
        state.set_mode(_MODES[args.mode])
    if args.fan is not None:
        state.set_fan_speed(_FANS[args.fan])
    if args.temp is not None:
        state.set_target_temp(args.temp)
    if args.louver is not None:
        state.set_vertical_louver(_LOUVERS[args.louver])
    if args.swing_lr is not None:
        state.set_swing_lr(args.swing_lr == "on")
    if args.turbo is not None:
        state.set_turbo(args.turbo == "on")
    if args.mute is not None:
        state.set_mute(args.mute == "on")
    if args.sleep is not None:
        state.set_sleep(args.sleep == "on")
    if args.display is not None:
        state.set_display(args.display == "on")
    if args.mildew is not None:
        state.set_mildew(args.mildew == "on")
    if args.health is not None:
        state.set_health(args.health == "on")
    if args.power_limit is not None:
        state.set_power_limit(None if args.power_limit < 0 else args.power_limit)
    return state.to_command(seq=args.seq)


def cmd_replay(args) -> int:
    """Разбирает записанный дамп линии.

    Понимает два формата: текстовый лог с hex-байтами (как в README, со
    скобками и метками направления) и сырой бинарный файл (``--binary``).
    """
    if args.binary:
        with open(args.file, "rb") as fh:
            data = fh.read()
    else:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            data = _parse_hex_log(fh.read())

    dec = StreamDecoder()
    packets = dec.feed(data)
    counters = {}
    for packet in packets:
        key = "TYPE=0x%02X%s" % (
            packet.ptype,
            "" if packet.cmd is None else " CMD=0x%02X" % packet.cmd,
        )
        counters[key] = counters.get(key, 0) + 1
        if not args.summary:
            print(_packet_report(packet, as_json=args.json, show_bits=args.bits))

    print("\nИтого: %d байт, %d кадров, отброшено %d байт." % (len(data), len(packets), dec.dropped_bytes))
    bad = sum(1 for p in packets if not p.crc_ok)
    if bad:
        print("Кадров с ошибкой CRC: %d." % bad)
    for key, count in sorted(counters.items()):
        print("  %-22s %d" % (key, count))
    return 0


def cmd_ports(args) -> int:
    from aux_hvac import list_ports
    from aux_hvac.transport.base import TransportError

    try:
        ports = list_ports()
    except TransportError as exc:
        print(exc)
        return 2
    if not ports:
        print("Последовательные порты не найдены.")
        return 1
    for line in ports:
        print(line)
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
        prog="aux_tool.py",
        description="Офлайн-инструмент для проверки протокола AUX HVAC.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("selftest", help="прогнать все примеры из README")
    p.add_argument("-q", "--quiet", action="store_true", help="печатать только итог и ошибки")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("crc", help="посчитать контрольную сумму")
    p.add_argument("data", nargs="+", help="байты в hex")
    p.set_defaults(func=cmd_crc)

    p = sub.add_parser("decode", help="разобрать кадр или несколько кадров подряд")
    p.add_argument("data", nargs="+", help="байты в hex")
    p.add_argument("--json", action="store_true", help="вывод в JSON")
    p.add_argument("--bits", action="store_true", help="показать побайтную раскладку")
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("encode", help="собрать известный пакет")
    p.add_argument(
        "what",
        choices=["ping", "ping-request", "indoor", "outdoor", "init", "0b", "control"],
        help="что собрать",
    )
    p.add_argument("--module", action="store_true", help="для ping: собрать ответ модуля, а не запрос сплита")
    p.add_argument("--seq", type=lambda s: int(s, 0), default=0x01, help="байт 9 (?X), по умолчанию 0x01")
    p.add_argument("--counter", type=lambda s: int(s, 0), default=0x01, help="счётчик для пакета 0x0B")
    p.add_argument("--base", help="исходное состояние для control: 13 байт тела или кадр 0x11 целиком")
    p.add_argument("--power", type=_on_off, help="включить/выключить сплит")
    p.add_argument("--mode", choices=sorted(_MODES), help="режим работы")
    p.add_argument("--fan", choices=sorted(_FANS), help="скорость вентилятора")
    p.add_argument("--temp", type=float, help="целевая температура, шаг 0.5")
    p.add_argument("--louver", choices=sorted(_LOUVERS), help="положение вертикальных шторок")
    p.add_argument("--swing-lr", type=_on_off, help="качание влево-вправо")
    p.add_argument("--turbo", type=_on_off, help="интенсивный режим")
    p.add_argument("--mute", type=_on_off, help="тихий режим")
    p.add_argument("--sleep", type=_on_off, help="ночной режим")
    p.add_argument("--display", type=_on_off, help="дисплей")
    p.add_argument("--mildew", type=_on_off, help="антиплесень")
    p.add_argument("--health", type=_on_off, help="ионизатор HEALTH")
    p.add_argument("--power-limit", type=int, help="лимит мощности инвертора, %% (отрицательное — снять)")
    p.add_argument("--json", action="store_true", help="вывод в JSON")
    p.add_argument("--bits", action="store_true", help="показать побайтную раскладку")
    p.add_argument("--raw", action="store_true", help="напечатать только hex-строку кадра")
    p.set_defaults(func=cmd_encode)

    p = sub.add_parser("replay", help="разобрать записанный дамп линии")
    p.add_argument("file", help="файл с дампом")
    p.add_argument("--binary", action="store_true", help="файл сырой бинарный, а не текстовый лог")
    p.add_argument("--summary", action="store_true", help="только сводка без покадрового вывода")
    p.add_argument("--json", action="store_true", help="вывод в JSON")
    p.add_argument("--bits", action="store_true", help="показать побайтную раскладку")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("ports", help="список доступных COM-портов")
    p.set_defaults(func=cmd_ports)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
