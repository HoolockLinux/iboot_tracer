from parse import *
from akf import *
from construct import Adapter, Int64ul, Int32ul, Int16ul, Int8ul, ExprAdapter, GreedyRange, ListContainer, StopFieldError, ExplicitError, StreamError

class ANS_Message(RTKMessage):
    EP      = 63, 56, Constant(0x20)

class ANS_Reply(ANS_Message):
    EP = 63, 56, Constant(0x20)
    STATUS = 15, 12
    TAG = 11, 4
    TYPE = 3, 0

class ANS_SetBase(ANS_Message):
    BASE = 51, 16
    UNK = 15, 4, Constant(0x118)
    IO = 1
    CMD = 0

class ANS_Cmd(ANS_Message):
    UNK = 31, 24
    ARG_2 = 19, 16 # (NSID * 2) & 0xf
    ARG_3 = 15, 12 # (NSID * 3) & 0xf
    NSID = 7, 4
    IO = 1
    CMD = 0

class ANS_IO_Cmd(ANS_Cmd):
    IO = 1

class ANS_Admin_Cmd(ANS_Cmd):
    IO = 1

def ans_i2a(asc: AKFParser, rel_ep: int, val):
    if rel_ep == 0:
        asc.print(f"[ansep] reply: {ANS_Reply(val)}")
    else:
        asc.print(f"message {RTKMessage(val)} received from  unknown rel app endpoint {rel_ep}")
    return

def ans_a2i(asc: AKFParser, rel_ep: int, val):
    if rel_ep != 0:
        asc.print(f"message {RTKMessage(val)} received from  unknown rel app endpoint {rel_ep}")
        return
    if ((val >> 4) & 0xfff) == 0x118:
        asc.print(f"[ansep] SetBase: {ANS_SetBase(val)}")
    elif ((val & 3) == 3):
        asc.print(f"[ansep] IO CMD: {ANS_IO_Cmd(val)}")
    elif ((val & 3) == 1):
        asc.print(f"[ansep] Admin CMD: {ANS_Admin_Cmd(val)}")
    else:
        raise Exception(f"[ansep] Not recognized ANS2 I2A message: {val:#x}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} /path/to/trace_log.txt <cpid>")
        exit(-1)
    f = open(sys.argv[1], 'r')
    s = f.read()
    chip_id = int(sys.argv[2], 16)

    ANS_MBOX = 0x208041000

    lines = s.split('\n')
    access_lines = []
    parsed_lines = []
    for line in lines:
        access_lines.append(parse_line(line))

    for line in access_lines:
        parsed_lines.append(line)

    akf = AKFParser(addr=ANS_MBOX, name="trace(ans1)", app_ep_i2a=ans_i2a, app_ep_a2i=ans_a2i)

    for access in parsed_lines:
        if type(access) is not Access:
            print(access)
            continue

        if access.pa > ANS_MBOX and access.pa < (ANS_MBOX+0x1000):
            akf.access_akf(access)
        else:
            print(access)

