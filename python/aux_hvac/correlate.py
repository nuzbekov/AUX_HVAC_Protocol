# -*- coding: utf-8 -*-
"""Сопоставление регистров RS485 с расшифрованными полями UART-протокола.

Зачем это нужно
===============

Кадровый уровень шины RS485 разобран, а смысл регистров — почти нет: см.
:mod:`aux_hvac.rs485_protocol`. Обычный способ расшифровки — снять два дампа
до и после изменения одной величины — работает, но даёт по одному регистру за
опыт. На семнадцать регистров одного только кадра ``CMD=0x02`` уйдёт семнадцать
пар дампов, и это при условии, что каждую величину удастся подвигать отдельно.

Здесь используется то, что у платы **два интерфейса сразу**: разъём
wifi-модуля с UART-протоколом, где семантика известна вся, и шина RS485, где
она неизвестна. Если слушать оба одновременно, то каждое изменение любой
величины сразу даёт готовую пару «известное поле — неизвестный регистр»: одна
сессия закрывает столько регистров, сколько величин успели подвигаться.

Как считается совпадение
========================

Каждый раз, когда с шины приходит блок регистров, берётся снимок: значения
регистров и последние известные значения полей UART. По набору снимков для
каждой пары «поле, регистр» проверяется гипотеза ``регистр == поле * масштаб``.

Отсеиваются заведомо бессмысленные сопоставления:

* поле, которое за всю сессию не менялось, ни с чем не сопоставляется — с
  постоянным значением совпадёт что угодно. То же для регистра;
* совпадение должно держаться почти на всех снимках, а не на некоторых;
* пара «поле, регистр» должна совпасть в нескольких **разных** значениях, а
  не в одном: иначе достаточно одного случайного совпадения.

Считать доли по снимкам нельзя: снимки не независимы. Шина повторяет один и
тот же цикл, поэтому сотня снимков — это те же двадцать состояний, а ещё
часть снимков попадает ровно в момент перехода, когда UART уже обновился, а
шина ещё нет. На живом железе такой одинокий переходный снимок сбивал верное
соответствие с 100% до 99%, то есть шум и сигнал оказывались неотличимы.

Поэтому снимки группируются **по значению поля UART**, и внутри группы у
регистра берётся устойчивое значение — то, которое встречалось чаще всего.
Переходные снимки при этом оказываются в меньшинстве своей группы и ни на
что не влияют, а сто повторов одного состояния дают ровно один голос.

Дальше порог строгий: надёжным считается соответствие, верное для **всех**
значений поля. Проверено на живом железе: при таком подсчёте верные
соответствия дают 100%, а ложные вида «бит регистра с комнатной температурой
= питание» разваливаются.

Поэтому всё, что не дотянуло до 100%, попадает в отдельный список догадок и
прямо называется догадками. Неверно подписанный регистр хуже
неподписанного: его перестают проверять.

Одно и то же место кадра описывается по-разному — как 16-битное слово и как
пара байтов, — поэтому найденные соответствия схлопываются к самому узкому
описанию: бит байта понятнее, чем бит слова.

Масштабы проверяются оба, и это важно: UART отдаёт температуру целыми
градусами и половинами, а шина — десятыми долями, поэтому ``масштаб = 10``
для температур и ``масштаб = 1`` для счётчиков и флагов.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__all__ = [
    "Correlator",
    "Match",
    "Sample",
    "numeric_fields",
    "SCALES",
    "RAW_WORD_BASE",
    "RAW_BYTE_BASE",
    "where",
    "BITFIELD_WIDTHS",
    "MIN_PURITY",
]

#: Смещение ключей для 16-битных слов нагрузки, не разобранной как регистры.
#:
#: Настоящие регистры нумеруются небольшими числами, поэтому база выбрана
#: заведомо выше — так одно не путается с другим ни в ключах, ни в отчёте.
RAW_WORD_BASE = 1000

#: Смещение ключей для отдельных байтов такой нагрузки.
RAW_BYTE_BASE = 2000

#: Какую долю группы должно занять значение регистра, чтобы считаться
#: устойчивым.
#:
#: Если внутри одного значения поля регистр разбегается по нескольким
#: значениям, связи между ними нет — и правило большинства такое
#: противоречие только маскирует.
MIN_PURITY = 0.7

#: Ширины битовых полей, которые проверяются внутри значения.
#:
#: Однобитные — флаги вроде питания и дисплея. Двух- и трёхбитные — режим и
#: скорость вентилятора: в UART-протоколе они занимают по три бита, и на шине
#: оказались упакованы так же. Шире четырёх не ищем: осмысленных полей такой
#: ширины не встречалось, а число проверок растёт быстро.
BITFIELD_WIDTHS = (1, 2, 3)

#: Масштабы, в которых проверяется гипотеза «регистр = поле * масштаб».
#:
#: 10 — температуры: UART отдаёт градусы, шина десятые доли.
#: 1 — счётчики, проценты, номера режимов и флаги.
#: 2 — на случай, если величина хранится в половинах градуса.
SCALES = (10, 1, 2)


@dataclass
class Sample:
    """Снимок: значения регистров шины и полей UART в один момент."""

    t: float
    uart: Dict[str, float]
    regs: Dict[Tuple[int, int], int]


@dataclass
class Match:
    """Найденное соответствие поля UART и регистра шины."""

    field: str
    cmd: int
    reg: int
    scale: int
    agreement: float
    """Доля снимков, на которых гипотеза сошлась."""

    samples: int
    """Сколько разных значений поля участвовало в проверке."""

    distinct: int
    """Сколько разных устойчивых значений принимал сам регистр."""

    shift: int = 0
    """Сдвиг битового поля. Вместе с :attr:`width` = 0 значит «значение целиком»."""

    width: int = 0
    """Ширина битового поля. 0 — значение сравнивалось целиком."""

    one_to_one: bool = True
    """Взаимно ли однозначно соответствие.

    Если одно и то же значение регистра встречается при разных значениях
    поля, связь односторонняя, и расшифровкой считать её нельзя. Именно так
    отсеивается ложная находка «бит 6 регистра 200 = питание»: этот бит равен
    единице только при одном из значений регистра, а нулю — сразу при двух,
    причём при включённом питании тоже.
    """

    @property
    def place(self) -> str:
        """Место величины вместе с битами, если это битовое поле."""
        base = where(self.cmd, self.reg)
        if not self.width:
            return base
        if self.width == 1:
            return "%s бит %d" % (base, self.shift)
        return "%s биты %d..%d" % (base, self.shift + self.width - 1, self.shift)

    def describe(self) -> str:
        note = "" if self.one_to_one else ", связь односторонняя"
        return ("%-34s = %s%s   (сошлось на %d значениях поля из %d%s)"
                % (self.place, self.field,
                   "" if self.scale == 1 else " * %d" % self.scale,
                   int(round(self.agreement * self.samples)), self.samples,
                   note))


def _stable_by_field(pairs, min_purity: float = MIN_PURITY):
    """Устоявшееся значение регистра для каждого значения поля.

    Наивные варианты оба неверны, и это проверено на живом железе:

    * брать все снимки подряд нельзя — часть их попадает в момент перехода,
      когда UART уже показал новое значение, а шина ещё старое. Один такой
      снимок сбивал верное соответствие с «сошлось полностью» на «почти», и
      сигнал становился неотличим от шума;
    * брать самое частое значение в группе тоже нельзя — оно прячет редкие,
      но настоящие состояния. Регистр 200 при включённом питании принимал 64
      почти всегда и 128 только в режиме нагрева, и правило большинства
      выдало «бит 6 = питание», хотя в нагреве этот бит был нулём.

    Поэтому берётся значение, на котором регистр **устоялся**: самое частое
    во второй половине наблюдений группы. Переходные снимки всегда в начале,
    поэтому вторая половина от них свободна, а редкое состояние, если оно
    держится, во вторую половину попадает.

    Если и во второй половине значение не набрало ``min_purity``, группа
    считается противоречивой: связи между этим полем и этим регистром нет.

    Порядок ``pairs`` важен — он должен быть порядком наблюдений.

    Возвращает ``(устоявшиеся значения, сколько групп противоречивы)``.
    Противоречивые группы вызывающий код обязан считать несовпадением, иначе
    они просто исчезнут из статистики.
    """
    groups = {}
    for left, right in pairs:
        groups.setdefault(left, []).append(right)

    stable, ambiguous = {}, 0
    for left, values in groups.items():
        tail = values[len(values) // 2:] or values
        counts = {}
        for value in tail:
            counts[value] = counts.get(value, 0) + 1
        # при равенстве голосов берём меньшее значение, чтобы результат не
        # зависел от порядка перебора
        top = min(counts, key=lambda v: (-counts[v], v))
        if float(counts[top]) / len(tail) < min_purity:
            ambiguous += 1
            continue
        stable[left] = top
    return stable, ambiguous


def _is_one_to_one(stable, scale=1):
    """Проверяет, что соответствие однозначно в обе стороны.

    ``stable`` — отображение «значение поля -> устоявшееся значение регистра».
    Прямая однозначность в нём есть по построению, поэтому проверяется
    обратная: не приходится ли одно значение регистра на разные значения
    поля. Без этой проверки расшифрованным объявляется любое поле, которое
    просто иногда совпадает.
    """
    reverse = {}
    for left, right in stable.items():
        reverse.setdefault(right, set()).add(round(left * scale))
    return all(len(values) == 1 for values in reverse.values())


def where(cmd: int, reg: int) -> str:
    """Человекочитаемое место величины в кадре.

    Номера ниже :data:`RAW_WORD_BASE` — настоящие регистры блока, выше —
    сырые слова и байты нагрузки, которая как блок регистров не разобралась.
    """
    if reg >= RAW_BYTE_BASE:
        return "cmd=%02X байт @%d" % (cmd, reg - RAW_BYTE_BASE)
    if reg >= RAW_WORD_BASE:
        return "cmd=%02X слово @%d" % (cmd, reg - RAW_WORD_BASE)
    return "cmd=%02X рег %d" % (cmd, reg)


def numeric_fields(state) -> Dict[str, float]:
    """Приводит состояние блока к числам, пригодным для сопоставления.

    Логические поля становятся 0 и 1, перечисления — своими числовыми
    значениями, а всё, что числом не выражается (тексты вроде расшифровки
    кода ошибки), отбрасывается: сопоставлять текст с регистром бессмысленно.

    Отдельная забота — перечисления. ``to_dict`` отдаёт режим, скорость
    вентилятора и положения шторок **строками**, потому что так они читаются
    человеком. Для сопоставления нужны их числовые коды, поэтому строковое
    значение перепроверяется через сам объект состояния: если там
    перечисление, берётся его код.

    Без этого режим и скорость не сопоставлялись вовсе — а на шине именно они
    занимают большую часть упакованного байта состояния.
    """
    out: Dict[str, float] = {}
    for name, value in state.to_dict().items():
        if isinstance(value, bool):
            out[name] = 1.0 if value else 0.0
            continue
        if isinstance(value, (int, float)):
            out[name] = float(value)
            continue
        if hasattr(value, "value") and isinstance(getattr(value, "value"), int):
            out[name] = float(value.value)
            continue
        if isinstance(value, str):
            # строка могла получиться из перечисления — спросим исходник
            raw = getattr(state, name, None)
            code = getattr(raw, "value", None)
            if isinstance(code, int) and not isinstance(code, bool):
                out[name] = float(code)
        # прочие строки и None пропускаем сознательно
    return out


class Correlator:
    """Копит снимки и ищет соответствия «поле UART — регистр шины».

    :param min_agreement: доля снимков, ниже которой гипотеза не
        рассматривается вовсе. Надёжной она всё равно считается только при
        точном совпадении; остальное идёт в догадки.
    :param min_distinct: сколько разных значений поля обязано встретиться.
    :param min_samples: меньше этого числа снимков выводы не делаются.
    """

    #: Ниже этого соответствие считается догадкой, а не расшифровкой.
    EXACT = 1.0

    def __init__(
        self,
        min_agreement: float = 0.9,
        min_distinct: int = 2,
        min_samples: int = 4,
    ) -> None:
        self.min_agreement = min_agreement
        self.min_distinct = min_distinct
        self.min_samples = min_samples

        self.samples: List[Sample] = []
        self.raw_samples = 0
        """Сколько снимков пришло всего, включая повторы."""

        self._uart: Dict[str, float] = {}
        self._uart_seen = False

    # ------------------------------------------------------------ наполнение

    def add_uart(self, t: float, state) -> None:
        """Запоминает свежие значения полей UART.

        Снимок при этом не создаётся: снимки привязаны к приходу регистров,
        иначе одни и те же значения шины попадут в набор много раз и
        перекосят доли совпадений.
        """
        self._uart.update(numeric_fields(state))
        self._uart_seen = True

    def add_registers(self, t: float, cmd: int, index: int, values) -> bool:
        """Добавляет снимок по пришедшему блоку регистров.

        Возвращает False, если снимок не взят: пока с UART не пришло ни
        одного статуса, сопоставлять регистры не с чем.
        """
        if not self._uart_seen:
            return False
        regs = {(cmd, index + n): int(v) for n, v in enumerate(values)}
        return self._append(t, regs)

    def add_payload(self, t: float, cmd: int, payload: bytes) -> bool:
        """Добавляет снимок по нагрузке кадра, не разобранной как регистры.

        Часть кадров шины под модель «индекс, количество, значения» не
        подходит, но данные в них есть: например у ``CMD=0x01`` нагрузка
        ``12 00 01 04 00 00`` менялась вслед за уставкой. Выбрасывать такие
        кадры нельзя — тогда величины, которые лежат только в них, никогда не
        найдутся.

        Поэтому нагрузка раскладывается сразу двумя способами: как 16-битные
        слова big-endian и как отдельные байты. Что из этого осмысленно,
        покажет само сопоставление; лишние варианты отсеются, потому что
        совпадать они не будут.

        Ключи таких величин смещены на :data:`RAW_WORD_BASE` и
        :data:`RAW_BYTE_BASE`, чтобы не путались с номерами настоящих
        регистров.
        """
        if not self._uart_seen:
            return False
        regs = {}
        for offset in range(0, len(payload) - 1, 2):
            word = int.from_bytes(payload[offset:offset + 2], "big", signed=True)
            regs[(cmd, RAW_WORD_BASE + offset)] = word
        for offset, byte in enumerate(payload):
            regs[(cmd, RAW_BYTE_BASE + offset)] = byte
        return self._append(t, regs)

    def _append(self, t: float, regs) -> bool:
        """Добавляет снимок, отбрасывая дословные повторы предыдущего.

        Шина повторяет один и тот же цикл, поэтому за минуту приходят сотни
        одинаковых снимков. Если их все считать, доли совпадений раздуваются:
        «совпало 100% из 2000 снимков» звучит убедительно, хотя разных
        состояний было двадцать. Поэтому подряд идущие одинаковые снимки
        схлопываются, а сколько их пришло всего, видно в
        :attr:`raw_samples`.
        """
        self.raw_samples += 1
        if self.samples:
            last = self.samples[-1]
            if last.regs == regs and last.uart == self._uart:
                return False
        self.samples.append(Sample(t=t, uart=dict(self._uart), regs=regs))
        return True

    # ------------------------------------------------------------ разбор

    def _series(self):
        """Собирает по каждому полю и каждому регистру список значений."""
        fields: Dict[str, List[float]] = {}
        regs: Dict[Tuple[int, int], List[Optional[int]]] = {}
        for sample in self.samples:
            for name, value in sample.uart.items():
                fields.setdefault(name, []).append(value)
            for key, value in sample.regs.items():
                regs.setdefault(key, []).append(value)
        return fields, regs

    def matches(self) -> List[Match]:
        """Находит соответствия. Сортировка: сначала самые убедительные."""
        if len(self.samples) < self.min_samples:
            return []

        found: List[Match] = []
        # регистры собираем по ключу: у разных кадров номера перекрываются,
        # поэтому ключ — пара «команда, номер регистра»
        for key in sorted({k for s in self.samples for k in s.regs}):
            cmd, reg = key
            pairs_all = [(s.uart, s.regs[key]) for s in self.samples if key in s.regs]
            if len(pairs_all) < self.min_samples:
                continue
            if len({value for _, value in pairs_all}) < 2:
                continue          # регистр не двигался — сопоставлять не с чем

            for name in sorted({n for uart, _ in pairs_all for n in uart}):
                pairs = [(uart[name], value) for uart, value in pairs_all if name in uart]
                if len(pairs) < self.min_samples:
                    continue
                stable, ambiguous = _stable_by_field(pairs)
                if len(stable) + ambiguous < self.min_distinct:
                    continue      # поле не двигалось

                best = None
                total = len(stable) + ambiguous
                for scale in SCALES:
                    hits = sum(1 for left, right in stable.items()
                               if round(left * scale) == right)
                    # противоречивые группы считаем несовпадением: иначе
                    # достаточно было бы одной однородной группы из десяти
                    agreement = float(hits) / total
                    if best is None or agreement > best[1]:
                        best = (scale, agreement)
                scale, agreement = best
                if agreement >= self.min_agreement:
                    found.append(Match(
                        field=name, cmd=cmd, reg=reg, scale=scale,
                        agreement=agreement, samples=total,
                        distinct=len(set(stable.values())),
                        one_to_one=_is_one_to_one(stable, scale)))
                    continue

                # значение целиком не сошлось — пробуем битовые поля внутри
                # него: питание, дисплей, режим и скорость на шине упакованы
                # в один байт, и целиком такое значение ни с чем не совпадёт
                match = self._best_bitfield(name, cmd, reg, pairs)
                if match is not None:
                    found.append(match)

        found.sort(key=lambda m: (-m.agreement, -m.distinct, m.cmd, m.reg,
                                  m.shift))
        return self._collapse(found)

    @staticmethod
    def _place_key(match):
        """Канонический адрес величины, одинаковый для разных её описаний.

        Слово нагрузки и два байта нагрузки — это одни и те же биты линии.
        Без приведения к общему виду одно питание выводится трижды: как бит
        слова, как бит старшего байта и как бит самого слова целиком.
        """
        reg, shift, width = match.reg, match.shift, match.width
        if reg >= RAW_BYTE_BASE:
            # байт нагрузки: он и есть самое узкое описание
            return ("b", match.cmd, reg - RAW_BYTE_BASE, shift, width)
        if reg >= RAW_WORD_BASE and width:
            # бит слова — это бит одного из двух его байтов; приводим к байту,
            # чтобы одно и то же питание не выводилось и как бит 15 слова,
            # и как бит 7 старшего байта
            offset = reg - RAW_WORD_BASE
            if shift >= 8 and shift + width <= 16:
                return ("b", match.cmd, offset, shift - 8, width)
            if shift + width <= 8:
                return ("b", match.cmd, offset + 1, shift, width)
        return ("r", match.cmd, reg, shift, width)

    def _collapse(self, found):
        """Оставляет по одному описанию на каждое место и поле.

        Из равноценных описаний предпочитается байтовое: «бит 7 байта 0»
        понятнее, чем «бит 15 слова 0». Сортировка уже поставила вперёд
        самые убедительные, поэтому первое встреченное и оставляем.
        """
        # сначала байтовые описания, потом словесные — при равной
        # убедительности
        def preference(match):
            is_word = RAW_WORD_BASE <= match.reg < RAW_BYTE_BASE
            return (-match.agreement, 1 if is_word else 0, match.cmd,
                    match.reg, match.shift)

        seen = set()
        out = []
        for match in sorted(found, key=preference):
            key = (match.field, self._place_key(match))
            if key in seen:
                continue
            seen.add(key)
            out.append(match)
        out.sort(key=lambda m: (-m.agreement, -m.distinct, m.cmd, m.reg, m.shift))
        return out

    def reliable(self):
        """Соответствия, годные в расшифровку: точные и взаимно однозначные."""
        return [m for m in self.matches()
                if m.agreement >= self.EXACT and m.one_to_one]

    def guesses(self):
        """Всё остальное: неточное либо односторонее. Догадки, не факты."""
        return [m for m in self.matches()
                if m.agreement < self.EXACT or not m.one_to_one]

    def _best_bitfield(self, name, cmd, reg, pairs):
        """Ищет битовое поле внутри значения, повторяющее поле UART.

        Проверяются все положения и ширины из :data:`BITFIELD_WIDTHS`.
        Требования те же, что и к целому значению, плюс одно: само битовое
        поле обязано принимать больше одного значения. Без этого условие
        «совпало» выполняет любое постоянное поле нулевой ширины смысла.
        """
        best = None
        for width in BITFIELD_WIDTHS:
            mask = (1 << width) - 1
            for shift in range(0, 16 - width + 1):
                extracted = [(left, (right >> shift) & mask)
                             for left, right in pairs]
                stable, ambiguous = _stable_by_field(extracted)
                total = len(stable) + ambiguous
                if total < self.min_distinct:
                    continue
                if len(set(stable.values())) < 2:
                    continue      # само битовое поле не двигалось
                hits = sum(1 for left, right in stable.items()
                           if round(left) == right)
                agreement = float(hits) / total
                if agreement < self.min_agreement:
                    continue
                # из подходящих берём самое узкое поле: широкое, включающее
                # лишние нулевые биты, описывает величину хуже
                # сравниваем именно доли совпадения: best[0] — доля,
                # best[2] — ширина. Из равных по доле берём самое узкое поле:
                # широкое, захватившее лишние нулевые биты, описывает
                # величину хуже
                if best is None or (agreement, -width) > (best[0], -best[2]):
                    best = (agreement, shift, width, total,
                            len(set(stable.values())),
                            _is_one_to_one(stable))
        if best is None:
            return None
        agreement, shift, width, groups, distinct, one_to_one = best
        return Match(field=name, cmd=cmd, reg=reg, scale=1, agreement=agreement,
                     samples=groups, distinct=distinct,
                     shift=shift, width=width, one_to_one=one_to_one)

    def moved_registers(self):
        """Регистры, которые за сессию менялись. Ключ и набор значений."""
        moved = {}
        for key in sorted({k for s in self.samples for k in s.regs}):
            values = {s.regs[key] for s in self.samples if key in s.regs}
            if len(values) > 1:
                moved[key] = sorted(values)
        return moved

    def moved_fields(self):
        """Поля UART, которые за сессию менялись."""
        moved = {}
        for name in sorted({n for s in self.samples for n in s.uart}):
            values = {s.uart[name] for s in self.samples if name in s.uart}
            if len(values) > 1:
                moved[name] = sorted(values)
        return moved

    # ------------------------------------------------------------ отчёт

    def report_lines(self) -> List[str]:
        """Отчёт для человека. Честно говорит и о том, чего не вышло."""
        lines = ["Снимков: %d различных (всего пришло %d)"
             % (len(self.samples), self.raw_samples)]
        if len(self.samples) < self.min_samples:
            if self.raw_samples >= self.min_samples:
                # данных пришло много, но все снимки одинаковые
                lines.append("Все снимки одинаковые: за сессию не изменилось")
                lines.append("ничего — ни на шине, ни по UART. Подвигайте")
                lines.append("уставку, режим или скорость вентилятора.")
            else:
                lines.append("Снимков слишком мало для выводов (нужно хотя бы %d)."
                             % self.min_samples)
            return lines

        moved_regs = self.moved_registers()
        moved_flds = self.moved_fields()
        lines.append("Двигались регистры: %d, поля UART: %d"
                     % (len(moved_regs), len(moved_flds)))

        found = self.matches()
        reliable, guesses = self.reliable(), self.guesses()

        lines.append("")
        if reliable:
            lines.append("РАСШИФРОВАНО (совпало точно):")
            for match in reliable:
                lines.append("  " + match.describe())
        else:
            lines.append("Ни одного точного соответствия не набралось.")

        if guesses:
            lines.append("")
            lines.append("ДОГАДКИ (совпало не полностью — проверять отдельным опытом):")
            for match in guesses:
                lines.append("  " + match.describe())

        if not moved_flds:
            lines.append("")
            lines.append("Ни одно поле UART не изменилось: подвигайте что-нибудь")
            lines.append("с пульта — уставку, режим, скорость вентилятора.")
        elif not moved_regs:
            lines.append("")
            lines.append("Поля UART менялись, а регистры шины — нет.")
            lines.append("Похоже, эти величины шина не передаёт вовсе.")

        matched = {(m.cmd, m.reg) for m in found}
        silent = [k for k in moved_regs if k not in matched]
        if silent:
            lines.append("")
            lines.append("Двигались, но ни с чем не сошлись (%d):" % len(silent))
            for cmd, reg in silent:
                values = moved_regs[(cmd, reg)]
                shown = ", ".join(str(v) for v in values[:6])
                if len(values) > 6:
                    shown += ", ..."
                lines.append("  %-24s значения: %s" % (where(cmd, reg), shown))

        unmatched_fields = [n for n in moved_flds
                            if not any(m.field == n for m in found)]
        if unmatched_fields:
            lines.append("")
            lines.append("Поля UART, для которых регистр не нашёлся: %s"
                         % ", ".join(unmatched_fields))
        return lines
