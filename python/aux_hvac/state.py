# -*- coding: utf-8 -*-
"""Семантика тел пакетов: статус внутреннего и внешнего блока.

Соответствие полей и байтов взято из README:

* :class:`IndoorState`  — TYPE=0x07, CMD=0x11 (байты 8..22);
* :class:`OutdoorState` — TYPE=0x07, CMD=0x21 (байты 8..31).

Нерасшифрованные байты не выбрасываются, а складываются в ``unknown``,
чтобы их можно было логировать и исследовать дальше.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .const import (
    ERROR_CODES,
    Command,
    FanSpeed,
    HorizontalLouver,
    Mode,
    PacketType,
    RealFanSpeed,
    VerticalLouver,
)
from .packet import Packet, PacketError

__all__ = ["IndoorState", "OutdoorState", "decode_state", "enum_or_raw"]

#: Смещение тела относительно начала пакета. Байт 8 пакета = body[0].
_BODY_OFFSET = 8


def enum_or_raw(enum_cls, value):
    """Возвращает член перечисления либо сырое число, если значение неизвестно."""
    try:
        return enum_cls(value)
    except ValueError:
        return value


def _name(value) -> str:
    return value.name if hasattr(value, "name") else "0x%02X" % value


# ===========================================================================
#  Внутренний блок: TYPE=0x07 CMD=0x11 / тело команды TYPE=0x06 CMD=0x01
# ===========================================================================

@dataclass
class IndoorState:
    """Статус внутреннего блока (CMD=0x11).

    Объект хранит сырые 13 байт (байты 10..22 пакета) в :attr:`payload`
    и разбирает их в именованные поля. Мутаторы ``set_*`` правят именно
    сырые байты — так же, как это делает штатный wifi-модуль: запросил
    статус, поправил нужные биты, отправил обратно командой TYPE=0x06 CMD=0x01
    (README, раздел «Последовательности команд»).
    """

    payload: bytearray
    """Байты 10..22 пакета — ровно то, что уходит в тело команды управления."""

    seq: int = 0x01
    """Байт 8 (?X). Предположительно эхо байта 9 из запроса модуля."""

    cmd: int = Command.INDOOR
    """Байт 9 (CMD)."""

    # ------------------------------------------------------------ разбор

    @property
    def raw_ts(self) -> int:
        """Байт 10 (TS): целевая температура + положение вертикальных шторок."""
        return self.payload[0]

    @property
    def raw_sl(self) -> int:
        """Байт 11 (SL): положение горизонтальных шторок."""
        return self.payload[1]

    @property
    def raw_td(self) -> int:
        """Байт 12 (Td+TMR)."""
        return self.payload[2]

    @property
    def raw_sp(self) -> int:
        """Байт 13 (SP+TH): скорость вентилятора + часы таймера."""
        return self.payload[3]

    @property
    def raw_tb(self) -> int:
        """Байт 14 (TB+MT+TM): турбо/тихий режим + минуты таймера."""
        return self.payload[4]

    @property
    def raw_mo(self) -> int:
        """Байт 15 (MO): режим работы сплита."""
        return self.payload[5]

    @property
    def raw_en(self) -> int:
        """Байт 18 (EN): признаки включения."""
        return self.payload[8]

    @property
    def raw_fl(self) -> int:
        """Байт 20 (FL): дисплей и антиплесень."""
        return self.payload[10]

    @property
    def raw_pwr_lim(self) -> int:
        """Байт 21 (PWR_LIM): ограничение мощности инвертора."""
        return self.payload[11]

    @property
    def raw_tsd(self) -> int:
        """Байт 22 (Tsd): десятые доли целевой температуры."""
        return self.payload[12]

    # -- температура --------------------------------------------------------

    @property
    def target_temp(self) -> float:
        """Целевая температура, °C.

        Формула из README: ``8 + (байт10 >> 3) + 0.5 * (байт12 >> 7)``.
        """
        return 8 + (self.raw_ts >> 3) + 0.5 * (self.raw_td >> 7)

    @property
    def target_temp_reported(self) -> float:
        """Целевая температура с учётом десятых из байта 22 (Tsd).

        В командах модуля байт 22 всегда 0x00 (дробная часть едет в бите TD
        байта 12), но в ответных пакетах сплит дублирует её сюда.
        """
        return 8 + (self.raw_ts >> 3) + self.raw_tsd / 10.0

    @property
    def half_degree(self) -> bool:
        """Бит TD байта 12: у целевой температуры есть половина градуса."""
        return bool(self.raw_td & 0x80)

    # -- шторки -------------------------------------------------------------

    @property
    def vertical_louver(self):
        """Биты UD3..UD1 байта 10 (TS)."""
        return enum_or_raw(VerticalLouver, self.raw_ts & 0x07)

    @property
    def horizontal_louver(self):
        """Биты LR3..LR1 байта 11 (SL)."""
        return enum_or_raw(HorizontalLouver, self.raw_sl >> 5)

    @property
    def swing_lr(self) -> bool:
        """Качание влево-вправо включено.

        Для AUX и большинства систем значим только бит LR1. Для Rovex/Royal Clima
        качание включено, когда все три бита LR сброшены — этот случай тоже
        покрывается проверкой LR1 == 0.
        """
        return not (self.raw_sl & 0x20)

    # -- вентилятор и режим -------------------------------------------------

    @property
    def fan_speed(self):
        """Биты SP3..SP1 байта 13."""
        return enum_or_raw(FanSpeed, self.raw_sp >> 5)

    @property
    def turbo(self) -> bool:
        """Бит TB байта 14: интенсивный режим."""
        return bool(self.raw_tb & 0x40)

    @property
    def mute(self) -> bool:
        """Бит MT байта 14: тихий режим."""
        return bool(self.raw_tb & 0x80)

    @property
    def mode(self):
        """Биты MD3..MD1 байта 15 (MO)."""
        return enum_or_raw(Mode, self.raw_mo >> 5)

    @property
    def sleep(self) -> bool:
        """Бит SLP байта 15: ночной режим."""
        return bool(self.raw_mo & 0x04)

    @property
    def fahrenheit(self) -> bool:
        """Бит FH байта 15: температура на дисплее в градусах Фаренгейта."""
        return bool(self.raw_mo & 0x02)

    @property
    def ifeel(self) -> bool:
        """Бит iFL байта 15: режим iFeel.

        Через wifi не включается — только с ИК-пульта (README).
        """
        return bool(self.raw_mo & 0x08)

    # -- включение и функции ------------------------------------------------

    @property
    def power(self) -> bool:
        """Бит POW байта 18 (EN)."""
        return bool(self.raw_en & 0x20)

    @property
    def timer_enabled(self) -> bool:
        """Бит TMR байта 18 (EN)."""
        return bool(self.raw_en & 0x40)

    @property
    def clean(self) -> bool:
        """Бит iCL байта 18: режим самоочистки iCLEAN (при POW=0)."""
        return bool(self.raw_en & 0x04)

    @property
    def health(self) -> bool:
        """Бит HL2 байта 18: функция HEALTH (ионизатор)."""
        return bool(self.raw_en & 0x02)

    @property
    def health_status(self) -> bool:
        """Бит HL1-SFT байта 18.

        Сплит поднимает его сам: у старых моделей — при работе ионизатора,
        у моделей 2025 года — при включении функции SOFT (мягкий поток).
        """
        return bool(self.raw_en & 0x01)

    @property
    def display(self) -> bool:
        """Бит DS байта 20 (FL).

        ВАЖНО: у части моделей (Rovex и, возможно, других) логика инвертирована,
        см. issue #31 к компоненту aux_ac.
        """
        return bool(self.raw_fl & 0x10)

    @property
    def mildew(self) -> bool:
        """Бит MD байта 20 (FL): функция «антиплесень»."""
        return bool(self.raw_fl & 0x08)

    # -- таймер и мощность --------------------------------------------------

    @property
    def timer_hours(self) -> int:
        """Биты TH5..TH1 байта 13: часы таймера (максимум 23)."""
        return self.raw_sp & 0x1F

    @property
    def timer_minutes(self) -> int:
        """Биты TM5..TM1 байта 14: минуты таймера."""
        return self.raw_tb & 0x1F

    @property
    def minutes_since_ir(self) -> int:
        """Биты TMR6..TMR1 байта 12: минут с последней команды ИК-пульта (0..59)."""
        return self.raw_td & 0x3F

    @property
    def power_limit_enabled(self) -> bool:
        """Бит LIM_EN байта 21."""
        return bool(self.raw_pwr_lim & 0x80)

    @property
    def power_limit(self) -> int:
        """Биты LIM7..LIM1 байта 21: ограничение мощности инвертора, %."""
        return self.raw_pwr_lim & 0x7F

    @property
    def unknown(self) -> Dict[str, int]:
        """Нерасшифрованные байты тела."""
        return {"byte16": self.payload[6], "byte17": self.payload[7], "byte19": self.payload[9]}

    # ------------------------------------------------------------ мутаторы

    def set_power(self, on: bool) -> "IndoorState":
        """Включает/выключает сплит (бит POW байта 18)."""
        self.payload[8] = (self.payload[8] | 0x20) if on else (self.payload[8] & ~0x20 & 0xFF)
        return self

    def set_mode(self, mode: Mode) -> "IndoorState":
        """Задаёт режим работы (биты MD байта 15)."""
        self.payload[5] = (self.payload[5] & 0x1F) | ((int(mode) & 0x07) << 5)
        return self

    def set_fan_speed(self, speed: FanSpeed) -> "IndoorState":
        """Задаёт скорость вентилятора (биты SP байта 13)."""
        self.payload[3] = (self.payload[3] & 0x1F) | ((int(speed) & 0x07) << 5)
        return self

    def set_target_temp(self, temp: float) -> "IndoorState":
        """Задаёт целевую температуру с шагом 0,5 °C.

        Кратно формуле из README: целая часть уезжает в биты T5..T1 байта 10,
        половина градуса — в бит TD байта 12.
        """
        half = abs(temp - int(temp)) >= 0.25
        whole = int(temp) - 8
        if not 0 <= whole <= 31:
            raise ValueError("температура %s вне диапазона 8..39 °C" % temp)
        self.payload[0] = (self.payload[0] & 0x07) | (whole << 3)
        self.payload[2] = (self.payload[2] | 0x80) if half else (self.payload[2] & 0x7F)
        return self

    def set_vertical_louver(self, position: VerticalLouver) -> "IndoorState":
        """Задаёт положение вертикальных шторок (биты UD байта 10)."""
        self.payload[0] = (self.payload[0] & 0xF8) | (int(position) & 0x07)
        return self

    def set_swing_lr(self, on: bool) -> "IndoorState":
        """Включает/выключает качание влево-вправо (биты LR байта 11).

        Выключение выставляет все три бита LR в 1 — такой вариант понимают
        и AUX (значим только LR1), и Rovex/Royal Clima.
        """
        self.payload[1] = (self.payload[1] & 0x1F) if on else (self.payload[1] | 0xE0)
        return self

    def set_turbo(self, on: bool) -> "IndoorState":
        """Бит TB байта 14."""
        self.payload[4] = (self.payload[4] | 0x40) if on else (self.payload[4] & ~0x40 & 0xFF)
        return self

    def set_mute(self, on: bool) -> "IndoorState":
        """Бит MT байта 14."""
        self.payload[4] = (self.payload[4] | 0x80) if on else (self.payload[4] & ~0x80 & 0xFF)
        return self

    def set_sleep(self, on: bool) -> "IndoorState":
        """Бит SLP байта 15. Доступен только в режимах COOL и HEAT."""
        self.payload[5] = (self.payload[5] | 0x04) if on else (self.payload[5] & ~0x04 & 0xFF)
        return self

    def set_display(self, on: bool) -> "IndoorState":
        """Бит DS байта 20. У части моделей логика инвертирована."""
        self.payload[10] = (self.payload[10] | 0x10) if on else (self.payload[10] & ~0x10 & 0xFF)
        return self

    def set_mildew(self, on: bool) -> "IndoorState":
        """Бит MD байта 20: функция «антиплесень»."""
        self.payload[10] = (self.payload[10] | 0x08) if on else (self.payload[10] & ~0x08 & 0xFF)
        return self

    def set_health(self, on: bool) -> "IndoorState":
        """Бит HL2 байта 18. Бит HL1-SFT трогать нельзя — им рулит сплит."""
        self.payload[8] = (self.payload[8] | 0x02) if on else (self.payload[8] & ~0x02 & 0xFF)
        return self

    def set_clean(self, on: bool) -> "IndoorState":
        """Режим iCLEAN: байт 18 целиком выставляется в 0x04 (POW должен быть 0)."""
        self.payload[8] = 0x04 if on else (self.payload[8] & ~0x04 & 0xFF)
        return self

    def set_power_limit(self, percent: Optional[int]) -> "IndoorState":
        """Ограничение мощности инвертора, % (или None, чтобы снять).

        Минимум по приложению AC Freedom — 30 %.
        """
        if percent is None:
            self.payload[11] &= 0x7F
        else:
            if not 0 <= percent <= 100:
                raise ValueError("ограничение мощности %s вне диапазона 0..100" % percent)
            self.payload[11] = 0x80 | percent
        return self

    def set_timer(self, hours: int = 0, minutes: int = 0, enabled: bool = True) -> "IndoorState":
        """Задаёт таймер: часы в байт 13, минуты в байт 14, флаг в байт 18."""
        if not 0 <= hours <= 23:
            raise ValueError("часы таймера %s вне диапазона 0..23" % hours)
        if not 0 <= minutes <= 31:
            raise ValueError("минуты таймера %s вне диапазона 0..31" % minutes)
        self.payload[3] = (self.payload[3] & 0xE0) | hours
        self.payload[4] = (self.payload[4] & 0xE0) | minutes
        self.payload[8] = (self.payload[8] | 0x40) if enabled else (self.payload[8] & ~0x40 & 0xFF)
        return self

    # ------------------------------------------------------------ кодек

    @classmethod
    def from_packet(cls, packet: Packet) -> "IndoorState":
        """Разбирает пакет TYPE=0x07 CMD=0x11 или TYPE=0x06 CMD=0x01."""
        body = packet.body
        if len(body) < 15:
            raise PacketError("тело статуса внутреннего блока короче 15 байт")
        return cls(payload=bytearray(body[2:15]), seq=body[0], cmd=body[1])

    def to_command(self, seq: int = 0x01) -> Packet:
        """Собирает команду управления TYPE=0x06 CMD=0x01 из текущего состояния."""
        from .packet import control

        return control(bytes(self.payload), seq=seq)

    def copy(self) -> "IndoorState":
        return IndoorState(payload=bytearray(self.payload), seq=self.seq, cmd=self.cmd)

    # ------------------------------------------------------------ вывод

    def to_dict(self) -> Dict[str, Any]:
        return {
            "power": self.power,
            "mode": _name(self.mode),
            "target_temp": self.target_temp,
            "target_temp_reported": self.target_temp_reported,
            "fan_speed": _name(self.fan_speed),
            "turbo": self.turbo,
            "mute": self.mute,
            "sleep": self.sleep,
            "ifeel": self.ifeel,
            "fahrenheit": self.fahrenheit,
            "vertical_louver": _name(self.vertical_louver),
            "horizontal_louver": _name(self.horizontal_louver),
            "swing_lr": self.swing_lr,
            "display": self.display,
            "mildew": self.mildew,
            "health": self.health,
            "health_status": self.health_status,
            "clean": self.clean,
            "timer_enabled": self.timer_enabled,
            "timer_hours": self.timer_hours,
            "timer_minutes": self.timer_minutes,
            "minutes_since_ir": self.minutes_since_ir,
            "power_limit_enabled": self.power_limit_enabled,
            "power_limit": self.power_limit,
            "unknown": self.unknown,
        }

    def describe(self) -> str:
        return (
            "внутренний блок: %s, режим %s, цель %.1f°C, вентилятор %s%s%s, "
            "шторки V=%s LR=%s, дисплей %s, антиплесень %s"
            % (
                "ВКЛ" if self.power else "выкл",
                _name(self.mode),
                self.target_temp,
                _name(self.fan_speed),
                ", TURBO" if self.turbo else "",
                ", MUTE" if self.mute else "",
                _name(self.vertical_louver),
                "swing" if self.swing_lr else "off",
                "вкл" if self.display else "выкл",
                "вкл" if self.mildew else "выкл",
            )
        )


# ===========================================================================
#  Внешний блок: TYPE=0x07 CMD=0x21 (и дежурные пакеты CMD=0x20..0x2F)
# ===========================================================================

@dataclass
class OutdoorState:
    """Статус внешнего блока (CMD=0x21 либо дежурный пакет 0x20..0x2F)."""

    payload: bytes
    """Байты 10..31 пакета."""

    seq: int = 0x01
    """Байт 8 (?X)."""

    cmd: int = Command.OUTDOOR
    """Байт 9 (CMD). Для дежурных пакетов — значение из диапазона 0x20..0x2F."""

    @property
    def periodic(self) -> bool:
        """Дежурный пакет, разосланный сплитом без запроса."""
        return self.cmd != Command.OUTDOOR and 0x20 <= self.cmd <= 0x2F

    # -- байт 10 (CONF) -----------------------------------------------------

    @property
    def raw_conf(self) -> int:
        return self.payload[0]

    @property
    def inverter(self) -> bool:
        """Бит INV байта 10: инверторный сплит."""
        return bool(self.raw_conf & 0x20)

    @property
    def stationary(self) -> bool:
        """Бит 7 байта 10: 1 у стационарных, 0 у мобильного кондиционера Ballu."""
        return bool(self.raw_conf & 0x80)

    @property
    def periodic_flag(self) -> bool:
        """Бит iPRD байта 10: признак автоматической рассылки (только у инверторов)."""
        return bool(self.raw_conf & 0x04)

    # -- байт 11 (MODE) -----------------------------------------------------

    @property
    def raw_mode(self) -> int:
        return self.payload[1]

    @property
    def power(self) -> bool:
        """Бит PWR байта 11."""
        return bool(self.raw_mode & 0x01)

    @property
    def mode(self):
        """Биты MD3..MD1 байта 11. Кодировка та же, что у байта 15 пакета 0x11."""
        return enum_or_raw(Mode, self.raw_mode >> 5)

    @property
    def cooling_down(self) -> bool:
        """Байт 11 == 0x80: выход из HEAT, сплит ещё остывает."""
        return self.raw_mode == 0x80

    @property
    def sleep(self) -> bool:
        """Бит SLP байта 11."""
        return bool(self.raw_mode & 0x02)

    @property
    def louvers_on(self) -> bool:
        """Бит LON байта 11."""
        return bool(self.raw_mode & 0x10)

    @property
    def horizontal_louver(self) -> bool:
        """Бит HL байта 11."""
        return bool(self.raw_mode & 0x08)

    @property
    def vertical_louver(self) -> bool:
        """Бит VL байта 11.

        ВАЖНО: у Rovex ALS этот бит инвертирован (README).
        """
        return bool(self.raw_mode & 0x04)

    # -- байт 12 (FRST) -----------------------------------------------------

    @property
    def raw_frst(self) -> int:
        return self.payload[2]

    @property
    def clean(self) -> bool:
        """Бит CL байта 12: включена функция iCLEAN."""
        return bool(self.raw_frst & 0x80)

    @property
    def defrost(self) -> bool:
        """Бит DF байта 12: идёт разморозка внешнего блока."""
        return bool(self.raw_frst & 0x20)

    @property
    def need_defrost(self) -> bool:
        """Бит NDF байта 12. Расшифровка спорная, у части моделей всегда 0."""
        return bool(self.raw_frst & 0x10)

    # -- байты 13, 14 (вентилятор) -----------------------------------------

    @property
    def real_fan_speed(self):
        """Биты FS3..FS1 байта 13.

        Значения достоверны только в ответах на запрос модуля (CMD=0x21);
        в дежурных пакетах здесь другие, нерасшифрованные значения.
        """
        return enum_or_raw(RealFanSpeed, self.payload[3] & 0x07)

    @property
    def fan_pwm(self) -> int:
        """Байт 14 (FPWM) целиком.

        README разбивает байт на FP7..FP1 и один нерасшифрованный бит 0, но
        ориентировочные пороги (turbo 126..128, hi 100..113, mid 84..85,
        low 59..62, off 0) даны для значения байта целиком. Поэтому отдаём
        сырой байт, а бит 0 — отдельно в :attr:`fan_pwm_flag`.
        """
        return self.payload[4]

    @property
    def fan_pwm_flag(self) -> bool:
        """Бит 0 байта 14. Назначение неизвестно, встречался у Rovex ALS."""
        return bool(self.payload[4] & 0x01)

    # -- температуры --------------------------------------------------------

    @property
    def indoor_temp(self) -> float:
        """Температура внутреннего датчика, °C.

        Формула из README: ``байт15 - 0x20 + байт31 / 10``.
        """
        return self.payload[5] - 0x20 + (self.payload[21] & 0x0F) / 10.0

    @property
    def return_temp_raw(self) -> int:
        """Байт 17 (To). Похоже на температуру подачи/обратки.

        Достоверной формулы нет. Brokly предлагает трактовать значение как
        увеличенное на 0x20, см. :attr:`return_temp_hint`.
        """
        return self.payload[7]

    @property
    def return_temp_hint(self) -> int:
        """Гипотеза Brokly для байта 17: ``T - 0x20``. Требует проверки."""
        return self.payload[7] - 0x20

    @property
    def outdoor_temp(self) -> Optional[float]:
        """Байт 20: температура внешнего блока, ``T - 0x20``.

        Возвращает None, если датчика нет (в байте 0x00 — так у Rovex ALS).
        ВАЖНО: при выключенном кондиционере значение обновляется раз в 6-7 часов.
        """
        raw = self.payload[10]
        return None if raw == 0 else raw - 0x20

    @property
    def compressor_temp(self) -> Optional[float]:
        """Байты TCMP1..TCMP7 байта 22: температура компрессора, ``T - 0x20``.

        None для on-off кондиционеров (там 0x00) и для инверторов без датчика
        (там 0x20, что дало бы 0 °C и было бы принято за реальное значение).
        """
        raw = self.payload[12] & 0x7F
        if raw in (0x00, 0x20):
            return None
        return raw - 0x20

    @property
    def compressor_heater(self) -> bool:
        """Бит 7 байта 22. Предположительно запрос подогрева внешнего блока."""
        return bool(self.payload[12] & 0x80)

    @property
    def inverter_power(self) -> int:
        """Байт 24 (iPwr): мощность внешнего блока, % (0..100). У on-off всегда 0."""
        return self.payload[14]

    # -- ошибки -------------------------------------------------------------

    @property
    def error_code(self) -> int:
        """Байт 29: код ошибки. 0x00 при нормальной работе."""
        return self.payload[19]

    @property
    def error_text(self) -> str:
        return ERROR_CODES.get(self.error_code, "неизвестный код 0x%02X" % self.error_code)

    @property
    def temp_fraction(self) -> int:
        """Биты T4..T1 байта 31 (Tid): десятые доли комнатной температуры."""
        return self.payload[21] & 0x0F

    @property
    def unknown(self) -> Dict[str, int]:
        """Нерасшифрованные байты тела (нумерация — как в README)."""
        idx = {
            "byte16": 6,
            "byte18": 8,
            "byte19": 9,
            "byte21": 11,
            "byte23": 13,
            "byte25": 15,
            "byte26": 16,
            "byte27": 17,
            "byte28": 18,
            "byte30": 20,
        }
        return {k: self.payload[v] for k, v in idx.items() if v < len(self.payload)}

    # ------------------------------------------------------------ кодек

    @classmethod
    def from_packet(cls, packet: Packet) -> "OutdoorState":
        """Разбирает пакет TYPE=0x07 с CMD=0x21 либо CMD из 0x20..0x2F."""
        body = packet.body
        if len(body) < 24:
            raise PacketError("тело статуса внешнего блока короче 24 байт")
        return cls(payload=bytes(body[2:26]), seq=body[0], cmd=body[1])

    # ------------------------------------------------------------ вывод

    def to_dict(self) -> Dict[str, Any]:
        return {
            "periodic": self.periodic,
            "inverter": self.inverter,
            "stationary": self.stationary,
            "power": self.power,
            "mode": _name(self.mode),
            "cooling_down": self.cooling_down,
            "sleep": self.sleep,
            "louvers_on": self.louvers_on,
            "horizontal_louver": self.horizontal_louver,
            "vertical_louver": self.vertical_louver,
            "clean": self.clean,
            "defrost": self.defrost,
            "need_defrost": self.need_defrost,
            "real_fan_speed": _name(self.real_fan_speed),
            "fan_pwm": self.fan_pwm,
            "indoor_temp": round(self.indoor_temp, 1),
            "return_temp_raw": self.return_temp_raw,
            "outdoor_temp": self.outdoor_temp,
            "compressor_temp": self.compressor_temp,
            "compressor_heater": self.compressor_heater,
            "inverter_power": self.inverter_power,
            "error_code": self.error_code,
            "error_text": self.error_text,
            "unknown": self.unknown,
        }

    def describe(self) -> str:
        outdoor = "н/д" if self.outdoor_temp is None else "%.0f°C" % self.outdoor_temp
        return (
            "внешний блок%s: %s, режим %s, в комнате %.1f°C, снаружи %s, "
            "вентилятор %s, мощность %d%%, ошибка: %s"
            % (
                " (дежурный)" if self.periodic else "",
                "ВКЛ" if self.power else "выкл",
                _name(self.mode),
                self.indoor_temp,
                outdoor,
                _name(self.real_fan_speed),
                self.inverter_power,
                self.error_text,
            )
        )


def decode_state(packet: Packet):
    """Разбирает тело пакета в :class:`IndoorState`/:class:`OutdoorState`.

    Возвращает None, если у пакета нет разбираемого состояния (ping, init,
    подтверждение команды, пакет 0x0B).
    """
    cmd = packet.cmd
    if cmd is None:
        return None

    if packet.ptype == PacketType.INFO:
        if cmd == Command.INDOOR:
            return IndoorState.from_packet(packet)
        if cmd == Command.OUTDOOR or 0x20 <= cmd <= 0x2F:
            return OutdoorState.from_packet(packet)
        return None

    if packet.ptype == PacketType.CMD and cmd == Command.CONTROL and len(packet.body) >= 15:
        # тело команды управления совпадает с телом статуса внутреннего блока
        return IndoorState.from_packet(packet)

    return None
