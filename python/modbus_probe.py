# -*- coding: utf-8 -*-
"""Проба: не отвечает ли плата фанкойла ещё и на стандартный Modbus RTU.

Собственный протокол шины (см. aux_hvac.rs485_protocol) — не Modbus: другой
стартовый байт, другой заголовок, другая модель адресации. Но сама CRC у
него ровно та же, что у Modbus RTU (CRC16/MODBUS), и это не редкость: платы
на общей универсальной прошивке иногда параллельно понимают оба протокола на
одной шине. Проверить это дёшево — вопрос в том, отвечает ли адрес 0x01
хоть что-то на функции 0x03/0x04 (чтение holding/input регистров).

Кадр строится честно по стандарту, без всякого отношения к формату 0x7E:

    [адрес 1] [функция 1] [начальный регистр 2, big-endian]
    [количество регистров 2, big-endian] [CRC16/MODBUS 2, little-endian]

Успешный ответ на 0x03/0x04:

    [адрес] [функция] [байт количества] [данные] [CRC]

Это только чтение. Ничего в контроллер не пишется.

Запуск:

    python modbus_probe.py -p COM9
    python modbus_probe.py -p COM9 --slave 1 --start 0 --end 64 --counts 1,2,4
"""
from __future__ import annotations

import argparse
import sys
import time

sys.path.insert(0, ".")

from aux_hvac.rs485_protocol import crc16_modbus  # noqa: E402
from aux_hvac.transport.base import TransportError  # noqa: E402
from aux_hvac.transport.rs485 import RS485Transport  # noqa: E402

READ_HOLDING = 0x03
READ_INPUT = 0x04

#: Сколько ждать ответа на один запрос. Кадр из шести байт плюс ответ на
#: 9600 бод укладываются в десятки миллисекунд; запас взят с большим
#: избытком, чтобы не потерять медленный ответ.
RESPONSE_WAIT = 0.25

#: Пауза между запросами: чтобы наш поток чтения успел закрыть предыдущее
#: окно ожидания и не перепутать ответ на один запрос с ответом на другой.
REQUEST_GAP = 0.05


def build_request(slave: int, function: int, start: int, count: int) -> bytes:
    body = bytes([
        slave, function,
        (start >> 8) & 0xFF, start & 0xFF,
        (count >> 8) & 0xFF, count & 0xFF,
    ])
    crc = crc16_modbus(body)
    return body + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


def parse_response(raw: bytes, slave: int, function: int):
    """Разбирает ответ на 0x03/0x04, если он есть и правилен.

    Возвращает ``(регистры, лишний хвост)`` или ``None``, если ``raw`` не
    похож на корректный ответ данной функции для данного адреса.
    """
    if len(raw) < 5:
        return None
    if raw[0] != slave or raw[1] != function:
        return None
    byte_count = raw[2]
    end = 3 + byte_count + 2
    if len(raw) < end:
        return None
    body, crc_lo, crc_hi = raw[:end - 2], raw[end - 2], raw[end - 1]
    if crc16_modbus(body) != (crc_hi << 8 | crc_lo):
        return None
    data = raw[3:3 + byte_count]
    if byte_count % 2 != 0:
        return None
    regs = [
        int.from_bytes(data[i:i + 2], "big")
        for i in range(0, byte_count, 2)
    ]
    return regs, raw[end:]


def probe(transport: RS485Transport, slave: int, function: int,
          start: int, count: int, verbose: bool):
    request = build_request(slave, function, start, count)
    transport.reset_input()
    transport.write(request)

    buf = b""
    deadline = time.monotonic() + RESPONSE_WAIT
    while time.monotonic() < deadline:
        chunk = transport.read(64)
        if chunk:
            buf += chunk
        else:
            time.sleep(0.002)

    if not buf:
        if verbose:
            print("  рег %3d x%-2d (%s): тишина" % (
                start, count, "holding" if function == READ_HOLDING else "input"))
        return None

    # ответ может начаться не с первого байта — если что-то из штатного
    # проприетарного цикла легло в то же окно, ищем нашу сигнатуру внутри
    for offset in range(len(buf)):
        parsed = parse_response(buf[offset:], slave, function)
        if parsed is not None:
            return parsed[0]

    if verbose:
        print("  рег %3d x%-2d: %d байт мусора/чужого трафика, не Modbus-ответ"
              % (start, count, len(buf)))
    return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-p", "--port", required=True, help="порт, например COM9")
    parser.add_argument("-b", "--baud", type=int, default=9600)
    parser.add_argument("--slave", type=lambda s: int(s, 0), default=0x01,
                        help="адрес слейва (по умолчанию 0x01 — плата с датчиками)")
    parser.add_argument("--slaves", default=None,
                        help="несколько адресов через запятую (перебивает --slave); "
                             "0x00 — широковещательный, ответа Modbus на него не "
                             "полагается, но плата на своей шине может вести себя "
                             "нестандартно")
    parser.add_argument("--start", type=int, default=0, help="первый регистр")
    parser.add_argument("--end", type=int, default=64,
                        help="до какого регистра пробовать (не включая)")
    parser.add_argument("--counts", default="1,2,4",
                        help="количества регистров через запятую (по умолчанию 1,2,4)")
    parser.add_argument("--functions", default="3,4",
                        help="функции через запятую: 3=holding, 4=input")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="печатать и неудачные попытки, не только находки")
    args = parser.parse_args(argv)

    counts = [int(c) for c in args.counts.split(",") if c]
    functions = [int(f) for f in args.functions.split(",") if f]
    slaves = ([int(s, 0) for s in args.slaves.split(",") if s]
              if args.slaves else [args.slave])

    transport = RS485Transport(port=args.port, baudrate=args.baud,
                               parity="N", timeout=0.1, address=slaves[0])
    try:
        transport.open()
    except TransportError as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        return 2

    print("Modbus RTU проба: слейвы %s, регистры %d..%d, количества %s, "
          "функции %s" % (["0x%02X" % s for s in slaves],
                          args.start, args.end, counts, functions))
    print("Только чтение — 0x03 (holding) и/или 0x04 (input). Ctrl+C — стоп.\n")

    hits = 0
    tried = 0
    try:
        for slave in slaves:
            for function in functions:
                for reg in range(args.start, args.end):
                    for count in counts:
                        tried += 1
                        regs = probe(transport, slave, function, reg, count, args.verbose)
                        if regs is not None:
                            hits += 1
                            print("НАХОДКА  слейв=0x%02X func=0x%02X рег=%d x%d -> %s"
                                  % (slave, function, reg, count, regs))
                        time.sleep(REQUEST_GAP)
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.")
    finally:
        transport.close()

    print("\nЗапросов отправлено: %d, ответов, похожих на Modbus: %d" % (tried, hits))
    if not hits:
        print("Ни одного ответа в формате Modbus RTU не получено — похоже, "
              "плата этот протокол не понимает.")
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
