from enum import Enum
from typing import Optional
import threading, traceback, bisect, copy, heapq, importlib, sys, itertools, time, os, functools, struct, re, signal
from construct import Adapter, Int64ul, Int32ul, Int16ul, Int8ul, ExprAdapter, GreedyRange, ListContainer, StopFieldError, ExplicitError, StreamError

class AccessType(Enum):
    READ = 1
    WRITE = 2

class AccessWidth(Enum):
    W8 = 0
    W16 = 1
    W32 = 2
    W64 = 3
    W128 = 4

REGEX_8_16_32_64 = "^((?:[0-9]|[a-f]){9}):(R|W) ((?:[0-9]|[a-f]){9})@((?:[0-9]|[a-f]){9})=((?:[0-9]|[a-f])+)-([0-4])\r?$"
REGEX_128 = "^((?:[0-9]|[a-f]){9}):(R|W) ((?:[0-9]|[a-f]){9})@((?:[0-9]|[a-f]){9})=((?:[0-9]|[a-f])+)-4\\|((?:[0-9]|[a-f]){9})@((?:[0-9]|[a-f]){9})=((?:[0-9]|[a-f])+)-4\r?$"

class Access:
    pc: int
    type: AccessType
    va: int
    pa: int
    val: int
    val_hi: Optional[int]
    width: AccessWidth

    def __repr__(self):
        s = f"{hex(self.pc)}: "
        if self.type == AccessType.READ:
            s += "read"
        elif self.type == AccessType.WRITE:
            s += "write"

        if self.width == AccessWidth.W8:
            s += "8"
        elif self.width == AccessWidth.W16:
            s += "16"
        elif self.width == AccessWidth.W32:
            s += "32"
        elif self.width == AccessWidth.W64 or self.width == AccessWidth.W128:
            s += "64"
        
        s += f"({hex(self.pa)}, {hex(self.val)});"

        if self.width != AccessWidth.W128:
            return s
        
        if self.type == AccessType.READ:
            s += "read"
        elif self.type == AccessType.WRITE:
            s += "write"

        s += f"64({hex(self.pa)}, {hex(self.val)});"

        return s

def parse_line(line: str):
    match = re.search(REGEX_8_16_32_64, line)
    a = Access()
    if match is not None:
        a.pc = int(match[1], base=16)
        a.type = AccessType.READ if match[2] == 'R' else AccessType.WRITE
        a.va = int(match[3], base=16)
        a.pa = int(match[4], base=16)
        a.val = int(match[5], base=16)
        a.width = AccessWidth(int(match[6], base=16))
        return a
    match = re.search(REGEX_128, line)
    if match is not None:
        a.pc = int(match[1], base=16)
        a.type = AccessType.READ if match[2] == 'R' else AccessType.WRITE
        a.va = int(match[3], base=16)
        a.pa = int(match[4], base=16)
        a.val = int(match[5], base=16)
        a.width = AccessWidth.W128
        if a.va + 8 != int(match[6], base=16):
            raise ValueError("Unexpected VA_hi")
        if a.pa + 8 != int(match[7], base=16):
            raise ValueError("Unexpected PA_hi")
        a.val_hi = int(match[8], base=16)
        return a
    return line


class SafeGreedyRange(GreedyRange):
    def __init__(self, subcon, discard=False):
        super().__init__(subcon)
        self.discard = discard

    def _parse(self, stream, context, path):
        discard = self.discard
        obj = ListContainer()
        try:
            for i in itertools.count():
                context._index = i
                e = self.subcon._parsereport(stream, context, path)
                if not discard:
                    obj.append(e)
        except StreamError:
            pass
        return obj

class ReloadableMeta(type):
    _load_time: float
    def __new__(cls, name, bases, dct):
        m = super().__new__(cls, name, bases, dct)
        m._load_time = time.time()
        return m

class Reloadable(metaclass=ReloadableMeta):
    @classmethod
    def _reloadcls(cls, force=False):
        mods = []
        for c in cls.mro():
            mod = sys.modules[c.__module__]
            cur_cls = getattr(mod, c.__name__)
            mods.append((cur_cls, mod))
            if c.__name__ == "Reloadable":
                break

        reloaded = set()
        newest = 0
        for pcls, mod in mods[::-1]:
            source = getattr(mod, "__file__", None)
            if not source:
                continue
            newest = max(newest, os.stat(source).st_mtime, pcls._load_time)
            if (force or reloaded or pcls._load_time < newest) and mod.__name__ not in reloaded:
                print(f"Reload: {mod.__name__}")
                mod = importlib.reload(mod)
                reloaded.add(mod.__name__)

        return getattr(mods[0][1], cls.__name__)

    def _reloadme(self):
        self.__class__ = self._reloadcls()


class Constant:
    def __init__(self, value):
        self.value = value

    def __call__(self, v):
        assert v == self.value
        return v

class RegisterMeta(ReloadableMeta):
    _fields_list: list[str]
    _fields: set[str]
    def __new__(cls, name, bases, dct):
        m = super().__new__(cls, name, bases, dct)

        f = {}

        if bases and bases[0] is not Reloadable:
            for cls in bases[0].mro():
                if cls is Reloadable:
                    break
                f.update({k: None for k,v in cls.__dict__.items()
                          if not k.startswith("_") and isinstance(v, (int, tuple))})

        f.update({k: None for k, v in dct.items()
                 if not k.startswith("_") and isinstance(v, (int, tuple))})

        m._fields_list = list(f.keys())
        m._fields = set(f.keys())

        return m

class Register(Reloadable, metaclass=RegisterMeta):
    _Constant = Constant
    def __init__(self, v=None, **kwargs):
        if v is not None:
            self._value = v
            for k in self._fields_list:
                getattr(self, k) # validate
        else:
            self._value = 0
            for k in self._fields_list:
                field = getattr(self.__class__, k)
                if isinstance(field, tuple) and len(field) >= 3 and isinstance(field[2], self._Constant):
                    setattr(self, k, field[2].value)

        for k,v in kwargs.items():
            setattr(self, k, v)

    def __getattribute__(self, attr):
        if attr.startswith("_") or attr not in self._fields:
            return object.__getattribute__(self, attr)

        field = getattr(self.__class__, attr)
        value = self._value

        if isinstance(field, int):
            return (value >> field) & 1
        elif isinstance(field, tuple):
            if len(field) == 2:
                msb, lsb = field
                ftype = int
            else:
                msb, lsb, ftype = field
            return ftype((value >> lsb) & ((1 << ((msb + 1) - lsb)) - 1))
        else:
            raise AttributeError(f"Invalid field definition {attr} = {field!r}")

    def __setattr__(self, attr, fvalue):
        if attr.startswith("_"):
            self.__dict__[attr] = fvalue
            return

        field = getattr(self.__class__, attr)

        value = self._value

        if isinstance(field, int):
            self._value = (value & ~(1 << field)) | ((fvalue & 1) << field)
        elif isinstance(field, tuple):
            if len(field) == 2:
                msb, lsb = field
            else:
                msb, lsb, ftype = field
            mask = ((1 << ((msb + 1) - lsb)) - 1)
            self._value = (value & ~(mask << lsb)) | ((fvalue & mask) << lsb)
        else:
            raise AttributeError(f"Invalid field definition {attr} = {field!r}")

    def __int__(self):
        return self._value

    def _field_val(self, field_name, as_repr=False):
        field = getattr(self.__class__, field_name)
        val = getattr(self, field_name)
        if isinstance(val, Enum):
            if as_repr:
                return str(val)
            else:
                msb, lsb = field[:2]
                if (msb - lsb + 1) > 3:
                    return f"0x{val.value:x}({val.name})"
                else:
                    return f"{val.value}({val.name})"
        elif not isinstance(val, int):
            return val
        elif isinstance(field, int):
            return val
        elif isinstance(field, tuple):
            msb, lsb = field[:2]
            if (msb - lsb + 1) > 3:
                return f"0x{val:x}"

        return val

    @property
    def fields(self):
        return {k: getattr(self, k) for k in self._fields_list}

    def str_fields(self):
        return ', '.join(f'{k}={self._field_val(k)}' for k in self._fields_list)

    def __str__(self):
        return f"0x{self._value:x} ({self.str_fields()})"

    def __repr__(self):
        return f"{type(self).__name__}({', '.join(f'{k}={self._field_val(k, True)}' for k in self._fields_list)})"

    def copy(self):
        return type(self)(self._value)

    @property
    def value(self):
        return self._value
    @value.setter
    def value(self, val):
        self._value = val

class Register8(Register):
    __WIDTH__ = 8

class Register16(Register):
    __WIDTH__ = 16

class Register32(Register):
    __WIDTH__ = 32

class Register64(Register):
    __WIDTH__ = 64

class RegAdapter(Adapter):
    def __init__(self, register):
        if register.__WIDTH__ == 64:
            subcon = Int64ul
        elif register.__WIDTH__ == 32:
            subcon = Int32ul
        elif register.__WIDTH__ == 16:
            subcon = Int16ul
        elif register.__WIDTH__ == 8:
            subcon = Int8ul
        else:
            raise ValueError("Invalid reg width")

        self.reg = register
        super().__init__(subcon)

    def _decode(self, obj, context, path):
        return self.reg(obj)

    def _encode(self, obj, context, path):
        return obj.value

class RangeMap(Reloadable):
    def __init__(self):
        self.__start = []
        self.__end = []
        self.__value = []

    def clone(self):
        r = type(self)()
        r.__start = list(self.__start)
        r.__end = list(self.__end)
        r.__value = [copy.copy(i) for i in self.__value]
        return r

    def __len__(self):
        return len(self.__start)

    def __nonzero__(self):
        return bool(self.__start)

    def __contains(self, pos, addr):
        if pos < 0 or pos >= len(self.__start):
            return False

        return self.__start[pos] <= addr and addr <= self.__end[pos]

    def __split(self, pos, addr):
        self.__start.insert(pos + 1, addr)
        self.__end.insert(pos, addr - 1)
        self.__value.insert(pos + 1, copy.copy(self.__value[pos]))

    def __zone(self, zone):
        if isinstance(zone, slice):
            zone = range(zone.start if zone.start is not None else 0,
                         zone.stop if zone.stop is not None else 1 << 64)
        elif isinstance(zone, int):
            zone = range(zone, zone + 1)

        return zone

    def lookup(self, addr, default=None):
        addr = int(addr)

        pos = bisect.bisect_left(self.__end, addr)
        if self.__contains(pos, addr):
            return self.__value[pos]
        else:
            return default

    def __iter__(self):
        return self.ranges()

    def ranges(self):
        return (range(s, e + 1) for s, e in zip(self.__start, self.__end))

    def items(self):
        return ((range(s, e + 1), v) for s, e, v in zip(self.__start, self.__end, self.__value))

    def _overlap_range(self, zone, split=False):
        zone = self.__zone(zone)
        if not zone:
            return 0, 0

        start = bisect.bisect_left(self.__end, zone.start)

        if split:
            # Handle left-side overlap
            if self.__contains(start, zone.start) and self.__start[start] != zone.start:
                self.__split(start, zone.start)
                start += 1
                assert self.__start[start] == zone.start

        for pos in range(start, len(self.__start)):
            if self.__start[pos] >= zone.stop:
                return start, pos
            if split and (self.__end[pos] + 1) > zone.stop:
                self.__split(pos, zone.stop)
                return start, pos + 1

        return start, len(self.__start)

    def populate(self, zone, default=[]):
        zone = self.__zone(zone)
        if len(zone) == 0:
            return

        start, stop = zone.start, zone.stop

        # Starting insertion point, overlap inclusive
        pos = bisect.bisect_left(self.__end, zone.start)

        # Handle left-side overlap
        if self.__contains(pos, zone.start) and self.__start[pos] != zone.start:
            self.__split(pos, zone.start)
            pos += 1
            assert self.__start[pos] == zone.start

        # Iterate through overlapping ranges
        while start < stop:
            if pos == len(self.__start):
                # Append to end
                val = copy.copy(default)
                self.__start.append(start)
                self.__end.append(stop - 1)
                self.__value.append(val)
                yield range(start, stop), val
                break

            assert self.__start[pos] >= start
            if self.__start[pos] > start:
                # Insert new range
                boundary = stop
                if pos < len(self.__start):
                    boundary = min(stop, self.__start[pos])
                val = copy.copy(default)
                self.__start.insert(pos, start)
                self.__end.insert(pos, boundary - 1)
                self.__value.insert(pos, val)
                yield range(start, boundary), val
                start = boundary
            else:
                # Handle right-side overlap
                if self.__end[pos] > stop - 1:
                    self.__split(pos, stop)
                # Add to existing range
                yield range(self.__start[pos], self.__end[pos] + 1), self.__value[pos]
                start = self.__end[pos] + 1

            pos += 1
        else:
            assert start == stop

    def overlaps(self, zone, split=False):
        start, stop = self._overlap_range(zone, split)
        for pos in range(start, stop):
            yield range(self.__start[pos], self.__end[pos] + 1), self.__value[pos]

    def replace(self, zone, val):
        zone = self.__zone(zone)
        if zone.start == zone.stop:
            return
        start, stop = self._overlap_range(zone, True)
        self.__start = self.__start[:start] + [zone.start] + self.__start[stop:]
        self.__end = self.__end[:start] + [zone.stop - 1] + self.__end[stop:]
        self.__value = self.__value[:start] + [val] + self.__value[stop:]

    def clear(self, zone=None):
        if zone is None:
            self.__start = []
            self.__end = []
            self.__value = []
        else:
            zone = self.__zone(zone)
            if zone.start == zone.stop:
                return
            start, stop = self._overlap_range(zone, True)
            self.__start = self.__start[:start] + self.__start[stop:]
            self.__end = self.__end[:start] + self.__end[stop:]
            self.__value = self.__value[:start] + self.__value[stop:]

    def compact(self, equal=lambda a, b: a == b, empty=lambda a: not a):
        if len(self) == 0:
            return

        new_s, new_e, new_v = [], [], []

        for pos in range(len(self)):
            s, e, v = self.__start[pos], self.__end[pos], self.__value[pos]
            if empty(v):
                continue
            if new_v and equal(last, v) and s == new_e[-1] + 1:
                new_e[-1] = e
            else:
                new_s.append(s)
                new_e.append(e)
                new_v.append(v)
                last = v

        self.__start, self.__end, self.__value = new_s, new_e, new_v

    def _assert(self, expect, val=lambda a:a):
        state = []
        for i, j, v in zip(self.__start, self.__end, self.__value):
            state.append((i, j, val(v)))
        if state != expect:
            print(f"Expected: {expect}")
            print(f"Got:      {state}")

class AddrLookup(RangeMap):
    def __str__(self):
        b = [""]
        for zone, values in self.items():
            b.append(f"{zone.start:#11x} - {zone.stop - 1:#11x}")
            if len(values) == 0:
                b.append(f" (empty range)")
            elif len(values) == 1:
                b.append(f" : {values[0][0]}\n")
            if len(values) > 1:
                b.append(f" ({len(values):d} devices)\n")
                for value, r in sorted(values, key=lambda r: r[1].start):
                    b.append(f"      {r.start:#10x} - {r.stop - 1:#8x} : {value}\n")

        return "".join(b)

    def add(self, zone, value):
        for r, values in self.populate(zone):
            values.append((value, zone))

    def remove(self, zone, value):
        for r, values in self.overlaps(zone):
            try:
                values.remove((value, zone))
            except:
                pass

    def lookup(self, addr, default='unknown'):
        maps = super().lookup(addr)
        return maps[0] if maps else (default, range(0, 1 << 64))

    def lookup_all(self, addr):
        return super().lookup(addr, [])

    def _assert(self, expect, val=lambda a:a):
        super()._assert(expect, lambda v: [i[0] for i in v])

class ScalarRangeMap(RangeMap):
    def get(self, addr, default=None):
        return self.lookup(addr, default)

    def __setitem__(self, zone, value):
        self.replace(zone, value)

    def __delitem__(self, zone):
        self.clear(zone)

    def __getitem__(self, addr):
        value = self.lookup(addr, default=KeyError)
        if value is KeyError:
            raise KeyError(f"Address {addr:#x} has no value")
        return value

class BoolRangeMap(RangeMap):
    def set(self, zone):
        self.replace(zone, True)

    def __delitem__(self, zone):
        self.clear(zone)

    def __getitem__(self, addr):
        return self.lookup(addr, False)

class DictRangeMap(RangeMap):
    def __setitem__(self, k, value):
        if not isinstance(k, tuple):
            self.replace(k, dict(value))
        else:
            zone, key = k
            for r, values in self.populate(zone, {}):
                values[key] = value

    def __delitem__(self, k):
        if not isinstance(k, tuple):
            self.clear(k)
        else:
            zone, key = k
            for r, values in self.overlaps(zone, True):
                values.pop(key, None)

    def __getitem__(self, k):
        if isinstance(k, tuple):
            addr, k = k
            values = self.lookup(addr)
            return values.get(k, None) if values else None
        else:
            values = self.lookup(k)
            return values or {}

class SetRangeMap(RangeMap):
    def add(self, zone, key):
        for r, values in self.populate(zone, set()):
            values.add(key)

    def discard(self, zone, key):
        for r, values in self.overlaps(zone, split=True):
            if values:
                values.discard(key)
    remove = discard

    def __setitem__(self, k, value):
        self.replace(k, set(value))

    def __delitem__(self, k):
        self.clear(k)

    def __getitem__(self, addr):
        values = super().lookup(addr)
        return frozenset(values) if values else frozenset()

class NdRange:
    def __init__(self, rng, min_step=1):
        if isinstance(rng, range):
            self.ranges = [rng]
        else:
            self.ranges = list(rng)
        least_step = self.ranges[0].step
        for i, rng in enumerate(self.ranges):
            if rng.step == 1:
                self.ranges[i] = range(rng.start, rng.stop, min_step)
                least_step = min_step
            else:
                assert rng.step >= min_step
                least_step = min(least_step, rng.step)
        self.start = sum(rng[0] for rng in self.ranges)
        self.stop = sum(rng[-1] for rng in self.ranges) + least_step
        self.rev = {}
        for i in itertools.product(*map(enumerate, self.ranges)):
            index = tuple(j[0] for j in i)
            addr = sum(j[1] for j in i)
            if len(self.ranges) == 1:
                index = index[0]
            self.rev[addr] = index

    def index(self, item):
        return self.rev[item]

    def __len__(self):
        return self.stop - self.start

    def __contains__(self, item):
        return item in self.rev

    def __getitem__(self, item):
        if not isinstance(item, tuple):
            assert len(self.ranges) == 1
            return self.ranges[0][item]

        assert len(self.ranges) == len(item)
        if all(isinstance(i, int) for i in item):
            return sum((i[j] for i, j in zip(self.ranges, item)))
        else:
            iters = (i[j] for i, j in zip(self.ranges, item))
            return map(sum, itertools.product(*(([i] if isinstance(i, int) else i) for i in iters)))

class RegMapMeta(ReloadableMeta):
    def __new__(cls, name, bases, dct):
        m = super().__new__(cls, name, bases, dct)
        if getattr(m, "_addrmap", None) is None:
            m._addrmap = {}
            m._rngmap = SetRangeMap()
            m._namemap = {}
        else:
            m._addrmap = dict(m._addrmap)
            m._rngmap = m._rngmap.clone()
            m._namemap = dict(m._namemap)

        for k, v in dct.items():
            if k.startswith("_") or not isinstance(v, tuple):
                continue
            addr, rtype = v

            if isinstance(addr, int):
                m._addrmap[addr] = k, rtype
            else:
                addr = NdRange(addr, rtype.__WIDTH__ // 8)
                m._rngmap.add(addr, (addr, k, rtype))

            m._namemap[k] = addr, rtype

            def prop(k):
                def getter(self):
                    return self._accessor[k]
                def setter(self, val):
                    self._accessor[k].val = val
                return property(getter, setter)

            setattr(m, k, prop(k))

        return m

class RegAccessor(Reloadable):
    def __init__(self, cls, rd, wr, addr):
        self.cls = cls
        self.rd = rd
        self.wr = wr
        self.addr = addr

    def __int__(self):
        return self.rd(self.addr)

    @property
    def val(self):
        return self.rd(self.addr)

    @val.setter
    def val(self, value):
        self.wr(self.addr, int(value))

    @property
    def reg(self):
        val = self.val
        if val is None:
            return None
        return self.cls(val)

    @reg.setter
    def reg(self, value):
        self.wr(self.addr, int(value))

    def set(self, **kwargs):
        r = self.reg
        for k, v in kwargs.items():
            setattr(r, k, v)
        self.wr(self.addr, int(r))

    def __str__(self):
        return str(self.reg)

class RegArrayAccessor(Reloadable):
    def __init__(self, range, cls, rd, wr, addr):
        self.range = range
        self.cls = cls
        self.rd = rd
        self.wr = wr
        self.addr = addr

    def __getitem__(self, item):
        off = self.range[item]
        if isinstance(off, int):
            return RegAccessor(self.cls, self.rd, self.wr, self.addr + off)
        else:
            return [RegAccessor(self.cls, self.rd, self.wr, self.addr + i) for i in off]

class BaseRegMap(Reloadable):
    def __init__(self, backend, base):
        self._base = base
        self._backend = backend
        self._accessor = {}

        for name, (addr, rcls) in self._namemap.items():
            width = rcls.__WIDTH__
            rd = functools.partial(backend.read, width=width)
            wr = functools.partial(backend.write, width=width)
            if type(addr).__name__ == "NdRange":
                self._accessor[name] = RegArrayAccessor(addr, rcls, rd, wr, base)
            else:
                self._accessor[name] = RegAccessor(rcls, rd, wr, base + addr)

    def _lookup_offset(cls, offset):
        reg = cls._addrmap.get(offset, None)
        if reg is not None:
            name, rcls = reg
            return name, None, rcls
        ret = cls._rngmap[offset]
        if ret:
            for rng, name, rcls in ret:
                if offset in rng:
                    return name, rng.index(offset), rcls
        return None, None, None
    lookup_offset = classmethod(_lookup_offset)

    def lookup_addr(self, addr):
        return self.lookup_offset(addr - self._base)

    def get_name(self, addr):
        name, index, rcls = self.lookup_addr(addr)
        if index is not None:
            return f"{name}[{index}]"
        else:
            return name

    def _lookup_name(cls, name):
        return cls._namemap.get(name, None)
    lookup_name = classmethod(_lookup_name)

    def _scalar_regs(self):
        for addr, (name, rtype) in self._addrmap.items():
            yield addr, name, self._accessor[name], rtype

    def _array_reg(self, zone, map):
        addrs, name, rtype = map
        def index(addr):
            idx = addrs.index(addr)
            if isinstance(idx, tuple):
                idx = str(idx)[1:-1]
            return idx
        reg = ((addr, f"{name}[{index(addr)}]", self._accessor[name][addrs.index(addr)], rtype)
                     for addr in zone if addr in addrs)
        return reg

    def _array_regs(self):
        for zone, maps in self._rngmap.items():
            yield from heapq.merge(*(self._array_reg(zone, map) for map in maps))

    def dump_regs(self):
        for addr, name, acc, rtype in heapq.merge(sorted(self._scalar_regs()), self._array_regs()):
            print(f"{self._base:#x}+{addr:06x} {name} = {acc.reg}")

class RegMap(BaseRegMap, metaclass=RegMapMeta):
    pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        exit(1)
    f = open(sys.argv[1], 'r')
    s = f.read()
    lines = s.split('\n')
    for line in lines:
        print(parse_line(line))
