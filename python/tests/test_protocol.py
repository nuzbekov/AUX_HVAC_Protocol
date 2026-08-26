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


class TestRS485Stub(unittest.TestCase):
    """Заготовка RS485 должна честно сообщать, что не реализована."""

    def test_encoder_refuses_explicitly(self):
        from aux_hvac.rs485_protocol import NotDecodedYet, RS485Frame, request_status

        with self.assertRaises(NotDecodedYet):
            RS485Frame(raw=b"\x01\x02").encode()
        with self.assertRaises(NotDecodedYet):
            request_status(1)

    def test_raw_capture_still_works(self):
        """Снять дамп шины можно уже сейчас — это и есть смысл заготовки."""
        from aux_hvac.rs485_protocol import RS485Decoder

        dec = RS485Decoder()
        dec.feed(b"\x01\x02\x03")
        frames = dec.flush()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].raw, b"\x01\x02\x03")
        self.assertEqual(dec.flush(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
