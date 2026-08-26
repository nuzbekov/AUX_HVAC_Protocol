# -*- coding: utf-8 -*-
"""Тесты кодека. Только stdlib, ничего ставить не нужно.

    python python/tests/test_protocol.py     напрямую
    python -m unittest discover python/tests
    pytest python/tests                      если pytest всё-таки есть

Основной массив проверок живёт в ``aux_tool.py selftest`` — там они привязаны
к конкретным примерам пакетов из README и печатают человекочитаемый отчёт.
Здесь этот прогон обёрнут в один тест, а рядом лежат переборные проверки,
которые в отчёт по README не укладываются.
"""

from __future__ import annotations

import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from aux_hvac import (  # noqa: E402
    FanSpeed,
    IndoorState,
    Mode,
    Packet,
    PacketError,
    StreamDecoder,
    VerticalLouver,
    crc16_bytes,
    decode_state,
)


class TestReadmeExamples(unittest.TestCase):
    """Прогон всех проверок по примерам из README."""

    def test_selftest_passes(self):
        import aux_tool

        args = aux_tool.build_parser().parse_args(["selftest", "-q"])
        self.assertEqual(aux_tool.cmd_selftest(args), 0)


class TestIndoorStateBits(unittest.TestCase):
    """Поля внутреннего блока сидят в общих байтах и не должны мешать друг другу."""

    def test_target_temp_roundtrip(self):
        """Любая температура с шагом 0,5 °C кодируется и читается обратно."""
        for step in range(16, 79):
            temp = step / 2
            with self.subTest(temp=temp):
                state = IndoorState(payload=bytearray(13))
                state.set_target_temp(temp)
                self.assertEqual(state.target_temp, temp)

    def test_temp_out_of_range_rejected(self):
        state = IndoorState(payload=bytearray(13))
        for temp in (7.0, 40.0, -5.0):
            with self.subTest(temp=temp):
                with self.assertRaises(ValueError):
                    state.set_target_temp(temp)

    def test_mode_and_fan_are_independent(self):
        """Режим (байт 15) и скорость вентилятора (байт 13) не пересекаются."""
        for mode in Mode:
            for fan in FanSpeed:
                with self.subTest(mode=mode, fan=fan):
                    state = IndoorState(payload=bytearray(13))
                    state.set_mode(mode).set_fan_speed(fan).set_target_temp(21).set_power(True)
                    self.assertIs(state.mode, mode)
                    self.assertIs(state.fan_speed, fan)
                    self.assertEqual(state.target_temp, 21.0)
                    self.assertTrue(state.power)

    def test_louver_does_not_disturb_temp(self):
        """Шторки лежат в младших битах того же байта, что и целевая температура."""
        for louver in VerticalLouver:
            with self.subTest(louver=louver):
                state = IndoorState(payload=bytearray(13))
                state.set_target_temp(29.5).set_vertical_louver(louver)
                self.assertIs(state.vertical_louver, louver)
                self.assertEqual(state.target_temp, 29.5)

    def test_timer_does_not_disturb_fan_and_turbo(self):
        """Часы таймера делят байт 13 со скоростью, минуты — байт 14 с TURBO/MUTE."""
        state = IndoorState(payload=bytearray(13))
        state.set_fan_speed(FanSpeed.MEDIUM).set_turbo(True).set_mute(True)
        state.set_timer(hours=23, minutes=31)
        self.assertIs(state.fan_speed, FanSpeed.MEDIUM)
        self.assertTrue(state.turbo)
        self.assertTrue(state.mute)
        self.assertEqual((state.timer_hours, state.timer_minutes), (23, 31))

    def test_timer_out_of_range_rejected(self):
        state = IndoorState(payload=bytearray(13))
        with self.assertRaises(ValueError):
            state.set_timer(hours=24)
        with self.assertRaises(ValueError):
            state.set_timer(minutes=32)


class TestWireRoundtrip(unittest.TestCase):
    def test_command_survives_the_wire(self):
        """Команда собирается, уходит в линию и разбирается обратно без потерь."""
        state = IndoorState(payload=bytearray(13))
        state.set_power(True).set_mode(Mode.HEAT).set_target_temp(24.5)
        state.set_fan_speed(FanSpeed.HIGH).set_turbo(True).set_display(False).set_power_limit(60)

        back = decode_state(Packet.decode(state.to_command().encode()))

        self.assertEqual(back.payload, state.payload)
        self.assertTrue(back.power)
        self.assertTrue(back.turbo)
        self.assertIs(back.mode, Mode.HEAT)
        self.assertEqual(back.target_temp, 24.5)
        self.assertIs(back.fan_speed, FanSpeed.HIGH)
        self.assertFalse(back.display)
        self.assertEqual((back.power_limit_enabled, back.power_limit), (True, 60))

    def test_every_single_bit_flip_breaks_crc(self):
        """CRC ловит любую одиночную ошибку в кадре."""
        frame = bytearray(bytes.fromhex("bb00068000000f000101970002600020000000000000"))
        frame += crc16_bytes(bytes(frame))
        checked = 0
        for i in range(len(frame)):
            for bit in range(8):
                corrupted = bytearray(frame)
                corrupted[i] ^= 1 << bit
                if corrupted[0] != 0xBB or corrupted[6] != frame[6]:
                    continue  # испорчены START или LEN — это ловится раньше CRC
                checked += 1
                with self.subTest(byte=i, bit=bit):
                    with self.assertRaises(PacketError):
                        Packet.decode(bytes(corrupted))
        self.assertGreater(checked, 150)


class TestStreamDecoder(unittest.TestCase):
    #: Кадры из README, записаны с пробелами ради читаемости.
    FRAMES = [
        bytes.fromhex(hexstr.replace(" ", ""))
        for hexstr in (
            "BB 00 01 00 00 00 00 00 43 FF",
            "BB 00 06 80 00 00 02 00 11 01 2B 7E",
            "BB 00 07 00 00 00 18 00 01 21 C0 3D 00 02 54 3A 00 29 00 00 00 00 "
            "00 00 00 00 00 00 00 00 00 05 10 36",
        )
    ]

    def test_survives_arbitrary_chunking(self):
        """Кадры собираются при любом дроблении потока."""
        stream = b"".join(self.FRAMES)
        for chunk_size in range(1, len(stream) + 1):
            with self.subTest(chunk=chunk_size):
                dec = StreamDecoder()
                got = []
                for i in range(0, len(stream), chunk_size):
                    got.extend(dec.feed(stream[i:i + chunk_size]))
                self.assertEqual([p.raw for p in got], self.FRAMES)
                self.assertEqual(dec.dropped_bytes, 0)

    def test_resyncs_after_garbage_between_frames(self):
        """Мусор между кадрами не должен ронять разбор последующих."""
        garbage = bytes.fromhex("00ff12aa")
        stream = garbage.join([b""] + self.FRAMES)
        dec = StreamDecoder()
        got = dec.feed(stream)
        self.assertEqual([p.raw for p in got], self.FRAMES)
        self.assertGreater(dec.dropped_bytes, 0)

    def test_buffer_does_not_grow_without_bound(self):
        """Поток без единого стартового байта не должен копиться в памяти."""
        dec = StreamDecoder()
        for _ in range(100):
            dec.feed(b"\x00" * 256)
        self.assertEqual(dec.dropped_bytes, 100 * 256)


#: Один полный цикл обмена, снятый с шины контроллера фанкойла AUX.
#: Байты 0xFE между кадрами — не опечатка: это огрызки от переключения
#: направления линии, см. «Артефакты линии» в aux_hvac.rs485_protocol.
RS485_CYCLE = bytes.fromhex("".join((
    "7EF101550A00001135C6",
    "FE",
    "7E01F1022B031100110122014000C0FC10E400000000FA00C800C800F7"
    "0000000037011904010101329DB5",
    "7EF100A115000000000000000000000000110AF39B",
    "7EF1F112110A04000000000000000063A4",
    "7EF1F1121D170A00000000000000000000000000000000000000002459",
    "7EF1F112172E070000000000111904010100000000BB16",
    "7EF1F0A515C806000000000000000000000000F9F2",
    "7E01E1550A000011D3A9",
    "7EF1C1550A00001124C6",
    "7EF1C2550A00001124F5",
    "7EF1CF550A00001125E8",
    "7EF101550A00001135C6",
    "FE",
    "7E01F1010D1200010400007615",
    "7EF100A115000000000000000000000000110AF39B",
    "7EF1F112110A04000000000000000063A4",
    "7EF1F1121D170A00000000000000000000000000000000000000002459",
    "7EF1F112172E070000000000111904010100000000BB16",
    "7EF1F0A515C806000000000000000000000000F9F2",
    "7E01E1550A000011D3A9",
    "7EF1C1550A00001124C6",
    "7EF1C2550A00001124F5",
    "7EF1CF550A00001125E8",
)))

#: Сколько кадров и огрызков в этом цикле.
RS485_CYCLE_FRAMES = 22
RS485_CYCLE_RUNTS = 2


class TestRS485Frame(unittest.TestCase):
    """Кадровый уровень RS485 расшифрован — проверяем его на реальном дампе."""

    def frames(self):
        from aux_hvac.rs485_protocol import RS485Decoder

        dec = RS485Decoder()
        return dec.feed(RS485_CYCLE), dec

    def test_cycle_decodes_without_a_single_bad_crc(self):
        """CRC16/MODBUS должна сойтись на всех кадрах цикла."""
        frames, dec = self.frames()
        self.assertEqual(len(frames), RS485_CYCLE_FRAMES)
        self.assertEqual(dec.bad_crc, 0)
        self.assertTrue(all(f.crc_ok for f in frames))

    def test_line_turnaround_runt_is_counted_not_swallowed(self):
        """Огрызок 0xFE не должен ломать разбор, но и теряться молча тоже."""
        frames, dec = self.frames()
        self.assertEqual(dec.dropped_bytes, RS485_CYCLE_RUNTS)
        self.assertEqual(len(frames), RS485_CYCLE_FRAMES)

    def test_reencode_is_byte_exact(self):
        """Сборка кадра обязана давать те же байты, что пришли из линии."""
        frames, _ = self.frames()
        for frame in frames:
            self.assertEqual(frame.encode(), frame.raw)

    def test_length_byte_covers_whole_frame(self):
        """LEN — длина всего кадра, включая стартовый байт и CRC."""
        frames, _ = self.frames()
        for frame in frames:
            self.assertEqual(frame.raw[4], len(frame.raw))

    def test_request_status_matches_observed_poll(self):
        """Собранный опрос должен совпасть с наблюдённым байт в байт."""
        from aux_hvac.rs485_protocol import request_status

        self.assertEqual(request_status(0xF1, 0x01),
                         bytes.fromhex("7EF101550A00001135C6"))

    def test_every_single_bit_flip_breaks_crc(self):
        """Одиночная ошибка бита обязана ловиться контрольной суммой."""
        from aux_hvac.rs485_protocol import RS485Frame

        good = bytes.fromhex("7EF101550A00001135C6")
        for pos in range(1, len(good)):
            for bit in range(8):
                broken = bytearray(good)
                broken[pos] ^= 1 << bit
                self.assertFalse(
                    RS485Frame.decode(bytes(broken)).crc_ok,
                    "порча байта %d бита %d осталась незамеченной" % (pos, bit),
                )

    def test_register_block_model_holds_for_every_data_frame(self):
        """Нагрузка кадра с данными = индекс, количество и столько же слов."""
        frames, _ = self.frames()
        blocks = [f.block for f in frames if f.block is not None]
        self.assertEqual(len(blocks), 9)
        for block in blocks:
            self.assertEqual(len(block.encode()), 2 + 2 * block.count)
            self.assertEqual(block.count, len(block.items()))

    def test_temperatures_of_the_big_frame(self):
        """Регистры 10..13 кадра CMD=0x02 — это те самые 25.0/20.0/20.0/24.7."""
        frames, _ = self.frames()
        big = [f for f in frames if f.cmd == 0x02][0]
        block = big.block
        self.assertEqual(block.index, 3)
        self.assertEqual(block.count, 17)
        values = dict(block.items())
        self.assertEqual([values[r] for r in (10, 11, 12, 13)], [250, 200, 200, 247])
        self.assertAlmostEqual(block.as_celsius(values[10]), 25.0)
        self.assertAlmostEqual(block.as_celsius(values[13]), 24.7)
        # -100.8 похоже на «датчик не подключён», температурой это не считаем
        self.assertIsNone(block.as_celsius(values[7]))

    def test_register_values_are_big_endian(self):
        """Значения регистров big-endian, а CRC — little-endian. Так в линии."""
        frames, _ = self.frames()
        big = [f for f in frames if f.cmd == 0x02][0]
        # 0x00FA = 250; при обратном порядке вышло бы 0xFA00 = 64000
        self.assertEqual(dict(big.block.items())[10], 250)
        self.assertEqual(big.crc, big.raw[-2] | (big.raw[-1] << 8))

    def test_poll_frame_is_not_a_register_block(self):
        """Короткий опрос под модель регистров не подходит — и не должен."""
        frames, _ = self.frames()
        poll = [f for f in frames if f.cmd == 0x55][0]
        self.assertIsNone(poll.block)
        self.assertEqual(poll.payload, bytes([0x00, 0x00, 0x11]))

    def test_stream_survives_arbitrary_chunking(self):
        """Разбор не должен зависеть от того, как поток нарезан по чтениям."""
        from aux_hvac.rs485_protocol import RS485Decoder

        reference = [f.raw for f in self.frames()[0]]
        for size in range(1, 45):
            dec = RS485Decoder()
            got = []
            for k in range(0, len(RS485_CYCLE), size):
                got.extend(f.raw for f in dec.feed(RS485_CYCLE[k:k + size]))
            self.assertEqual(got, reference, "сломалось при чтении по %d байт" % size)

    def test_garbage_before_frames_is_dropped_not_fatal(self):
        """Мусор перед кадром отбрасывается, кадры после него читаются."""
        from aux_hvac.rs485_protocol import RS485Decoder

        dec = RS485Decoder()
        frames = dec.feed(b"\xff\x00\x7e\x01" + RS485_CYCLE)
        self.assertEqual(len(frames), RS485_CYCLE_FRAMES)
        self.assertGreaterEqual(dec.dropped_bytes, 4)

    def test_buffer_is_bounded_on_endless_garbage(self):
        """Поток без единого кадра не должен раздувать буфер."""
        from aux_hvac.rs485_protocol import RS485Decoder

        dec = RS485Decoder()
        for _ in range(100):
            self.assertEqual(dec.feed(b"\x00" * 256), [])
        self.assertEqual(dec.dropped_bytes, 100 * 256)

    def test_pipe_register_follows_the_heated_sensor(self):
        """Регистр 13 — датчик PIPE: прогрев феном поднял только его.

        Кадр снят с шины после прогрева датчика теплообменника
        строительным феном. В опорном цикле тот же регистр держал 247.
        Заодно проверяем, что разрешение здесь 0,1 градуса, а не 1 градус,
        как в байте 17 UART-протокола.
        """
        from aux_hvac.rs485_protocol import RS485Frame

        hot = RS485Frame.decode(bytes.fromhex(
            "7E01F1022B031100110122014000C0FC10E400000000FC00C800C802E4"
            "0000000037011904010101322DAC"))
        self.assertTrue(hot.crc_ok)
        values = dict(hot.block.items())
        self.assertEqual(values[13], 740)                    # 74,0 градуса
        self.assertAlmostEqual(hot.block.as_celsius(values[13]), 74.0)

        cold = [f for f in self.frames()[0] if f.cmd == 0x02][0]
        self.assertEqual(dict(cold.block.items())[13], 247)  # 24,7 градуса

        # изменился ровно один регистр, кроме дрейфа датчика комнаты
        moved = [reg for reg, was in dict(cold.block.items()).items()
                 if was != values[reg]]
        self.assertEqual(sorted(moved), [10, 13])

    def test_decoded_registers_are_labelled_per_command(self):
        """Подпись регистра привязана к команде: номера у команд перекрываются."""
        from aux_hvac.rs485_protocol import KNOWN_REGISTERS

        frames, _ = self.frames()
        big = [f for f in frames if f.cmd == 0x02][0]
        self.assertIn("PIPE", big.describe())

        # у CMD=0x12 тоже есть регистры 10..13, но они нулевые и датчиками
        # не являются — подписываться они не должны
        other = [f for f in frames if f.cmd == 0x12 and f.block.index == 10][0]
        self.assertNotIn("PIPE", other.describe())
        self.assertNotIn("ROOM", other.describe())
        self.assertEqual(set(KNOWN_REGISTERS), {(0x02, 10), (0x02, 13)})

    def test_bus_state_decodes_the_cmd01_frame(self):
        """Кадр CMD=0x01 несёт состояние блока — разобрано сопоставлением с UART.

        Значения сверены на живом железе: оба интерфейса одновременно давали
        одно и то же, включая половину градуса в уставке.
        """
        from aux_hvac.const import FanSpeed, Mode
        from aux_hvac.rs485_protocol import BusState, RS485Frame

        # байт 0 = 0x92: питание (бит 7), режим COOL (001), вентилятор HIGH (001)
        # байт 1 = 0x80: дисплей; байты 2..3 = 0x0104 = 260 = 26,0 градуса
        frame = RS485Frame.decode(RS485Frame(
            addr_a=0x01, addr_b=0xF1, cmd=0x01,
            payload=bytes([0x92, 0x80, 0x01, 0x04, 0x00, 0x00])).encode())
        self.assertTrue(frame.crc_ok)

        state = BusState().update(frame)
        self.assertIs(state.power, True)
        self.assertEqual(state.mode, Mode.COOL)
        self.assertEqual(state.fan_speed, FanSpeed.HIGH)
        self.assertIs(state.display, True)
        self.assertAlmostEqual(state.target_temp, 26.0)
        self.assertIn("режим COOL", state.describe())
        self.assertIn("вентилятор HIGH", state.describe())

    def test_bus_state_keeps_halves_of_a_degree(self):
        """Уставка 27,5 должна дойти без потерь: на шине это 275 десятых."""
        from aux_hvac.rs485_protocol import BusState, RS485Frame

        frame = RS485Frame.decode(RS485Frame(
            addr_a=0x01, addr_b=0xF1, cmd=0x01,
            payload=bytes([0x92, 0x80, 0x01, 0x13, 0x00, 0x00])).encode())
        self.assertAlmostEqual(BusState().update(frame).target_temp, 27.5)

    def test_bus_state_fills_only_what_the_frame_carries(self):
        """Величина, которой в кадре не было, обязана остаться неизвестной.

        Иначе «выключено» не отличить от «ещё не приходило».
        """
        from aux_hvac.rs485_protocol import BusState

        frames, _ = self.frames()
        state = BusState()
        big = [f for f in frames if f.cmd == 0x02][0]
        state.update(big)
        self.assertAlmostEqual(state.room_temp, 25.0)
        self.assertAlmostEqual(state.pipe_temp, 24.7)
        self.assertIsNone(state.power)          # питания в этом кадре нет
        self.assertIsNone(state.target_temp)
        self.assertIn("н/д", state.describe())

    def test_bus_state_ignores_broken_frames(self):
        """Кадр с несошедшейся CRC не должен портить состояние."""
        from aux_hvac.rs485_protocol import BusState, RS485Frame

        good = RS485Frame(addr_a=0x01, addr_b=0xF1, cmd=0x01,
                          payload=bytes([0x92, 0x80, 0x01, 0x04, 0x00, 0x00]))
        state = BusState().update(RS485Frame.decode(good.encode()))
        broken = bytearray(good.encode())
        broken[5] ^= 0xFF                       # портим байт состояния
        state.update(RS485Frame.decode(bytes(broken)))
        self.assertIs(state.power, True)         # осталось прежним
        self.assertAlmostEqual(state.target_temp, 26.0)

    def test_semantics_still_refuse_to_guess(self):
        """Смысл регистров не расшифрован — parse_status обязан это сказать."""
        from aux_hvac.rs485_protocol import NotDecodedYet, parse_status

        frames, _ = self.frames()
        with self.assertRaises(NotDecodedYet):
            parse_status(frames[1])


class TestCorrelator(unittest.TestCase):
    """Сопоставление регистров шины с полями UART.

    Главное требование к нему — не выдавать случайные совпадения за
    расшифровку: неверно подписанный регистр хуже неподписанного, потому что
    его перестают проверять.
    """

    ROOMS = [24.7, 25.3, 27.1, 31.4, 22.2, 26.8, 29.9, 24.0]

    def outdoor(self, room, outdoor=18):
        """Большой статус UART с заданной комнатной температурой."""
        from aux_hvac.state import OutdoorState

        state = OutdoorState(payload=bytearray(24))
        state.payload[5] = (int(room) + 0x20) & 0xFF        # байт 15
        state.payload[21] = round((room - int(room)) * 10)  # байт 31
        state.payload[10] = (outdoor + 0x20) & 0xFF         # байт 20
        return state

    def test_finds_a_real_relation_with_its_scale(self):
        """Регистр, повторяющий поле в десятых долях, должен найтись."""
        from aux_hvac.correlate import Correlator

        corr = Correlator()
        for n, room in enumerate(self.ROOMS):
            corr.add_uart(n, self.outdoor(room))
            corr.add_registers(n, 0x02, 13, [round(room * 10)])

        found = corr.matches()
        hit = [m for m in found if m.field == "indoor_temp"]
        self.assertTrue(hit, "настоящая связь не найдена")
        self.assertEqual((hit[0].cmd, hit[0].reg, hit[0].scale), (0x02, 13, 10))
        self.assertAlmostEqual(hit[0].agreement, 1.0)

    def test_constant_register_is_never_matched(self):
        """С постоянным регистром совпадёт что угодно — значит, ничего."""
        from aux_hvac.correlate import Correlator

        corr = Correlator()
        for n, room in enumerate(self.ROOMS):
            corr.add_uart(n, self.outdoor(room))
            corr.add_registers(n, 0x02, 20, [777])
        self.assertEqual(corr.matches(), [])
        self.assertNotIn((0x02, 20), corr.moved_registers())

    def test_noisy_register_is_not_matched(self):
        """Регистр, живущий своей жизнью, сопоставляться не должен."""
        from aux_hvac.correlate import Correlator

        corr = Correlator()
        for n, room in enumerate(self.ROOMS):
            corr.add_uart(n, self.outdoor(room))
            corr.add_registers(n, 0x02, 21, [n * 3 + 1])
        self.assertEqual([m for m in corr.matches() if m.reg == 21], [])

    def test_field_that_never_moved_is_not_matched(self):
        """Постоянное поле тоже не даёт права на вывод."""
        from aux_hvac.correlate import Correlator

        corr = Correlator()
        for n, room in enumerate(self.ROOMS):
            corr.add_uart(n, self.outdoor(room, outdoor=18))   # внешняя не меняется
            corr.add_registers(n, 0x02, 13, [round(room * 10)])
        self.assertNotIn("outdoor_temp", corr.moved_fields())
        self.assertEqual([m for m in corr.matches() if m.field == "outdoor_temp"], [])

    def test_registers_of_different_frames_do_not_collide(self):
        """Регистр 13 у CMD=0x02 и у CMD=0x12 — разные величины.

        Номера регистров у разных команд перекрываются, и если ключом взять
        только номер, значения одного кадра затрут другой.
        """
        from aux_hvac.correlate import Correlator

        corr = Correlator()
        for n, room in enumerate(self.ROOMS):
            corr.add_uart(n, self.outdoor(room))
            corr.add_registers(n, 0x02, 13, [round(room * 10)])
            corr.add_registers(n, 0x12, 13, [0])          # тёзка, но всегда ноль
        keys = set(corr.moved_registers())
        self.assertIn((0x02, 13), keys)
        self.assertNotIn((0x12, 13), keys)

    def test_no_verdict_without_uart_status(self):
        """Пока статуса UART не было, регистры сопоставлять не с чем."""
        from aux_hvac.correlate import Correlator

        corr = Correlator()
        self.assertFalse(corr.add_registers(0.0, 0x02, 13, [247]))
        self.assertEqual(corr.samples, [])
        self.assertIn("слишком мало", chr(10).join(corr.report_lines()))

    def test_report_says_what_to_do_when_nothing_moved(self):
        """Отчёт обязан подсказать, что опыт не дал данных, а не молчать.

        Именно этот случай легко спутать с «мало данных»: снимков пришло
        много, но все они одинаковые, потому что за сессию ничего не
        изменилось. Отчёт должен говорить второе, а не первое.
        """
        from aux_hvac.correlate import Correlator

        corr = Correlator()
        for n in range(6):
            corr.add_uart(n, self.outdoor(25.0))
            corr.add_registers(n, 0x02, 13, [250])
        self.assertEqual(corr.raw_samples, 6)
        self.assertEqual(len(corr.samples), 1)      # повторы схлопнулись
        text = chr(10).join(corr.report_lines())
        self.assertIn("Все снимки одинаковые", text)
        self.assertNotIn("слишком мало", text)

    def test_repeated_identical_samples_do_not_inflate_confidence(self):
        """Повтор одного и того же снимка не должен добавлять уверенности.

        Шина повторяет цикл, и без схлопывания получалось бы «совпало 100%
        из 2000 снимков» там, где разных состояний было пять.
        """
        from aux_hvac.correlate import Correlator

        corr = Correlator()
        for room in self.ROOMS:
            corr.add_uart(0, self.outdoor(room))
            for _ in range(50):                      # шина повторяет цикл
                corr.add_registers(0, 0x02, 13, [round(room * 10)])
        self.assertEqual(corr.raw_samples, len(self.ROOMS) * 50)
        self.assertEqual(len(corr.samples), len(self.ROOMS))
        hit = [m for m in corr.matches() if m.field == "indoor_temp"]
        self.assertTrue(hit)
        self.assertEqual(hit[0].samples, len(self.ROOMS))

    def test_packed_bitfields_are_found(self):
        """Питание и режим на шине упакованы в один байт — их надо находить.

        Целиком такой байт ни с чем не совпадёт, и именно поэтому первая
        версия коррелятора пропускала и питание, и дисплей, и режим.
        """
        from aux_hvac.correlate import Correlator

        class Fake:
            """Состояние с нужными полями: проверяем коррелятор, а не декодер."""

            def __init__(self, power, mode):
                self._d = {"power": bool(power), "mode": mode}

            def to_dict(self):
                return dict(self._d)

        corr = Correlator()
        # байт вида: бит 7 — питание, биты 6..4 — режим
        for n, (power, mode) in enumerate([(1, 1), (1, 4), (0, 4), (1, 6),
                                          (0, 1), (1, 0), (0, 0), (1, 2)]):
            corr.add_uart(n, Fake(power, mode))
            corr.add_registers(n, 0x01, 0, [(power << 7) | (mode << 4)])

        found = corr.matches()
        power_hit = [m for m in found if m.field == "power"]
        self.assertTrue(power_hit, "битовое поле питания не найдено")
        self.assertEqual((power_hit[0].shift, power_hit[0].width), (7, 1))
        self.assertIn("бит 7", power_hit[0].place)

        mode_hit = [m for m in found if m.field == "mode"]
        self.assertTrue(mode_hit, "битовое поле режима не найдено")
        self.assertEqual((mode_hit[0].shift, mode_hit[0].width), (4, 3))
        self.assertIn("биты 6..4", mode_hit[0].place)

    def test_text_fields_are_dropped(self):
        """Текстовые поля вроде расшифровки ошибки числами не считаются."""
        from aux_hvac.correlate import numeric_fields

        fields = numeric_fields(self.outdoor(25.0))
        self.assertIn("indoor_temp", fields)
        self.assertNotIn("error_text", fields)
        for name, value in fields.items():
            self.assertIsInstance(value, float, name)


class TestRS485Monitor(unittest.TestCase):
    """Панель мониторинга шины: она не должна выдавать догадки за показания."""

    @staticmethod
    def poll():
        """Загружает aux_poll.py как модуль: это скрипт, а не пакет."""
        import importlib.util
        import os

        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "aux_poll.py")
        spec = importlib.util.spec_from_file_location("aux_poll_for_tests", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def rows(self, data):
        from aux_hvac.rs485_protocol import RS485Decoder

        ap = self.poll()
        dec = RS485Decoder()
        seen = {}
        for frame in dec.feed(data):
            key = (frame.addr_a, frame.addr_b, frame.cmd, bytes(frame.payload[:2]))
            count = seen[key][2] + 1 if key in seen else 1
            seen[key] = (frame, 0.0, count)
        return ap._rs485_registers(seen)

    def test_degrees_shown_only_where_they_mean_something(self):
        """Ноль не должен становиться «0.0 °C», а 17 — «1.7 °C»."""
        rows = self.rows(RS485_CYCLE)
        values = {key: value for kind, key, _, value in rows if kind == "v"}

        by_reg = {}
        for kind, key, label, value in rows:
            if kind == "v" and isinstance(key, tuple) and key[0][2] == 0x02:
                by_reg[key[1]] = (label, value)

        # расшифрованные регистры — с градусами
        self.assertIn("°C", by_reg[10][1])
        self.assertIn("°C", by_reg[13][1])
        self.assertIn("ROOM", by_reg[10][0])
        self.assertIn("PIPE", by_reg[13][0])
        # нули и мелочь вроде 17 — без градусов, чтобы не врать
        self.assertNotIn("°C", by_reg[9][1])
        self.assertNotIn("°C", by_reg[3][1])
        # и заведомо не-температуры тоже
        self.assertNotIn("°C", by_reg[16][1])
        self.assertTrue(values, "панель не собрала ни одной строки")

    def test_same_register_number_in_different_frames_is_a_different_row(self):
        """Регистр 13 у CMD=0x02 и у CMD=0x12 — разные строки, не одна.

        Иначе отметка «изменилось» срабатывала бы на чужих значениях:
        подписи вроде «регистр 13» повторяются в разных группах кадров.
        """
        rows = self.rows(RS485_CYCLE)
        keys = [key for kind, key, _, _ in rows if kind == "v"]
        self.assertEqual(len(keys), len(set(keys)), "ключи строк панели совпали")

        reg13 = [key for key in keys if isinstance(key, tuple) and key[1] == 13]
        self.assertGreater(len(reg13), 1)          # он есть в двух группах
        self.assertEqual(len(set(reg13)), len(reg13))

    def test_frames_without_registers_are_collapsed(self):
        """Опросы сведены в один раздел, иначе панель не влезает в окно."""
        rows = self.rows(RS485_CYCLE)
        headers = [label for kind, _, label, _ in rows if kind == "h"]
        self.assertEqual(
            sum(1 for h in headers if "без блока регистров" in h), 1)
        # разделов с регистрами столько, сколько разных блоков
        self.assertEqual(sum(1 for h in headers if "регистры" in h), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
