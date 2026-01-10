from parse import *
from asc import *
from construct import Adapter, Int64ul, Int32ul, Int16ul, Int8ul, ExprAdapter, GreedyRange, ListContainer, StopFieldError, ExplicitError, StreamError


SMC_MBOX = 0x236808000
SMC_CPU_CONTROL = 0x236000100

class SMCMessageTypes:
    SMC_READ_KEY           = 0x10
    SMC_WRITE_KEY          = 0x11
    SMC_GET_KEY_BY_INDEX   = 0x12
    SMC_GET_KEY_INFO       = 0x13
    SMC_INITIALIZE         = 0x17
    SMC_NOTIFICATION       = 0x18
    SMC_RW_KEY             = 0x20

class SMCMessage(Register64):
    TYPE = 7, 0
    UNK = 11, 8, Constant(0)
    ID = 15, 12

class SMCInitialize(SMCMessage):
    TYPE = 7, 0, Constant(SMCMessageTypes.SMC_INITIALIZE)

class SMCGetKeyInfo(SMCMessage):
    TYPE = 7, 0, Constant(SMCMessageTypes.SMC_GET_KEY_INFO)
    KEY = 63, 32

class SMCGetKeyByIndex(SMCMessage):
    TYPE = 7, 0, Constant(SMCMessageTypes.SMC_GET_KEY_BY_INDEX)
    INDEX = 63, 32

class SMCWriteKey(SMCMessage):
    TYPE = 7, 0, Constant(SMCMessageTypes.SMC_WRITE_KEY)
    SIZE = 23, 16
    KEY = 63, 32

class SMCReadKey(SMCMessage):
    TYPE = 7, 0, Constant(SMCMessageTypes.SMC_READ_KEY)
    SIZE = 23, 16
    KEY = 63, 32

class SMCReadWriteKey(SMCMessage):
    TYPE = 7, 0, Constant(SMCMessageTypes.SMC_RW_KEY)
    RSIZE = 23, 16
    WSIZE = 31, 24
    KEY = 63, 32

class SMCResult(Register64):
    RESULT = 7, 0
    ID = 15, 12
    SIZE = 31, 16
    VALUE = 63, 32

class SMCError(Exception):
    pass

def str_4cc(cc4: int):

    pass

def smc_a2i(asc: ASCParser, rel_ep: int, val_lo: int, val_hi: int):
    if rel_ep != 0:
        asc.print(f"message sent to unkown rel app endpoint {rel_ep}")

    smsg = SMCMessage(val_lo)
    match smsg.TYPE:
        case SMCMessageTypes.SMC_READ_KEY:
            rk = SMCReadKey(val_lo)
            asc.print(f"SMC read key {rk.KEY.to_bytes(4, byteorder="big").decode("ascii")}: {rk}")
        case SMCMessageTypes.SMC_WRITE_KEY:
            wk = SMCWriteKey(val_lo)
            asc.print(f"SMC write key {wk.KEY.to_bytes(4, byteorder="big").decode("ascii")}: {wk}")
        case SMCMessageTypes.SMC_GET_KEY_BY_INDEX:
            gkbi = SMCGetKeyByIndex(val_lo)
            asc.print(f"SMC get key by index: {gkbi}")
        case SMCMessageTypes.SMC_GET_KEY_INFO:
            gki = SMCGetKeyInfo(val_lo)
            asc.print(f"SMC get key info {gki.KEY.to_bytes(4, byteorder="big").decode("ascii")}: {gki}")
        case SMCMessageTypes.SMC_INITIALIZE:
            smci = SMCInitialize(val_lo)
            asc.print(f"SMC init: {smci}")
        case SMCMessageTypes.SMC_NOTIFICATION:
            asc.print(f"SMC notification: {smsg}")
        case SMCMessageTypes.SMC_RW_KEY:
            smcrw = SMCReadWriteKey(val_lo)
            asc.print(f"SMC read/write key {smcrw.KEY.to_bytes(4, byteorder="big").decode("ascii")}: {smcrw}")
        case _:
            asc.print(f"Unknown SMC Message: {smsg}")

def smc_i2a(asc: ASCParser, rel_ep: int, val_lo: int, val_hi: int):
    if rel_ep != 0:
        asc.print(f"message received from unkown rel app endpoint {rel_ep}")

    smcr = SMCResult(val_lo)
    asc.print(f"SMC result: {smcr}")

REGEX_M = "^M:((?:[0-9]|[a-f])+)$"

def parse_smc_trace_hook(line: str) -> str:
    match = re.search(REGEX_M, line)
    if match is None:
        return line
    return f"trace(smc): SHMEM: 0x{match[1]}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        exit(-1)
    f = open(sys.argv[1], 'r')
    s = f.read()
    lines = s.split('\n')
    access_lines = []
    parsed_lines = []
    for line in lines:
        access_lines.append(parse_line(line))

    for line in access_lines:
        if type(line) is str:
            parsed_lines.append(parse_smc_trace_hook(line))
        else:
            parsed_lines.append(line)

    asc = ASCParser(addr=SMC_MBOX, name="trace(smc)", app_ep_a2i=smc_a2i, app_ep_i2a=smc_i2a)

    for access in parsed_lines:
        if type(access) is not Access:
            print(access)
            continue

        if access.pa > SMC_MBOX and access.pa < (SMC_MBOX+0x1000):
            asc.access_asc(access)
        else:
            print(access)

