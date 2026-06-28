from parse import *
from construct import Adapter, Int64ul, Int32ul, Int16ul, Int8ul, ExprAdapter, GreedyRange, ListContainer, StopFieldError, ExplicitError, StreamError

class DARTS5L8960XRegs(Enum):
    STREAM_COMMAND = 0x0
    TCR = 0xc
    ERROR = 0x10
    ERROR_ADDR_LO = 0x1c
    DIAG_CONFIG = 0x20
    BYPASS_ADDR = 0x2c
    FETCH_CONFIG = 0x30
    TTBR0_S0 = 0x40
    TTBR1_S0 = 0x44
    TTBR2_S0 = 0x48
    TTBR3_S0 = 0x4c
    TTBR0_S1 = 0x50
    TTBR1_S1 = 0x54
    TTBR2_S1 = 0x58
    TTBR3_S1 = 0x5c
    TTBR0_S2 = 0x60
    TTBR1_S2 = 0x64
    TTBR2_S2 = 0x68
    TTBR3_S2 = 0x6c
    TTBR0_S3 = 0x70
    TTBR1_S3 = 0x74
    TTBR2_S3 = 0x78
    TTBR3_S3 = 0x7c

def access_dart(base, access):
    off = access.pa - base

    if access.width != AccessWidth.W32:
        self.print(f"DART access {access} width not supported")
        return

    print(f"{str(access.type).split(".")[1]} {DARTS5L8960XRegs(off)}: {hex(access.val)}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} /path/to/trace_log.txt <dart_address>")
        exit(-1)
    f = open(sys.argv[1], 'r')
    s = f.read()
    DART = int(sys.argv[2], 16)

    lines = s.split('\n')
    access_lines = []
    parsed_lines = []
    for line in lines:
        access_lines.append(parse_line(line))

    for line in access_lines:
        parsed_lines.append(line)

    for access in parsed_lines:
        if type(access) is not Access:
            print(access)
            continue

        if access.pa >= DART and access.pa < (DART+0x4000):
            access_dart(DART, access)
        else:
            print(access)
