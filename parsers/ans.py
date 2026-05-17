from parse import *
from asc import *
from construct import Adapter, Int64ul, Int32ul, Int16ul, Int8ul, ExprAdapter, GreedyRange, ListContainer, StopFieldError, ExplicitError, StreamError

class NVMeRegs(Enum):
    NVME_CAP = 0x0
    NVME_CAP_HI = 0x4

    NVME_CC = 0x14
    NVME_CSTS = 0x1c

    NVME_AQA = 0x24
    NVME_ASQ_LO = 0x28
    NVME_ASQ_HI = 0x2c
    NVME_ACQ_LO = 0x30
    NVME_ACQ_HI = 0x34

    NVME_ASQ_DB = 0x1000
    NVME_ACQ_DB = 0x1004
    NVME_IOSQ_DB = 0x1008
    NVME_IOCQ_DB = 0x100c

    NVME_BOOT_STATUS = 0x1300
    NVME_BOOT_STATUS_HI = 0x1304


class NVMeParser:
    def __init__(self, addr: int, name: str):
        self.addr = addr
        self.name = name
    def print(self, *values):
        print(f"{self.name}:", *values)
        pass
    def access_nvm(self, access: Access):
        off = access.pa - self.addr

        if access.width != AccessWidth.W32:
            self.print(f"NVME access {access} width not supported")
            return
        
        self.print(f"{str(access.type).split(".")[1]} {NVMeRegs(off)}: {hex(access.val)}")
    

# ASMI seems to be for passing data between ans and ans2 with AP in between

def ans_a2i(asc: ASCParser, rel_ep: int, val_lo: int, val_hi: int):
    if rel_ep == 1:
        asc.print(f"sending ASMI SMC->ANS2 Message: {hex(val_lo)}")
    else:
        asc.print(f"message lo={hex(val_lo)} sent to unknown rel app endpoint {rel_ep}")
    return

def ans_i2a(asc: ASCParser, rel_ep: int, val_lo: int, val_hi: int):
    if rel_ep == 1:
        asc.print(f"received ASMI ANS2->SMC Message: {hex(val_lo)}")
    else:
        asc.print(f"message lo={hex(val_lo)} receivedfrom  unknown rel app endpoint {rel_ep}")
    return

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} /path/to/trace_log.txt <0x8012|0x8015>")
        print(f"T2 is 0x8012 and A11 is 0x8015")
        exit(-1)
    f = open(sys.argv[1], 'r')
    s = f.read()
    chip_id = int(sys.argv[2], 16)

    ANS_MBOX = None
    ANS_NVME_BAR = None
    if chip_id == 0x8015:
        ANS_MBOX = 0x257008000
        ANS_NVME_BAR = 0x259cc0000
    elif chip_id == 0x8012:
        ANS_MBOX = 0x303008000
        ANS_NVME_BAR = 0x304cc0000
    else:
        print("Unsupported chip")
        exit(-1)

    lines = s.split('\n')
    access_lines = []
    parsed_lines = []
    for line in lines:
        access_lines.append(parse_line(line))

    for line in access_lines:
        parsed_lines.append(line)

    asc = ASCParser(addr=ANS_MBOX, name="trace(ans)", app_ep_a2i=ans_a2i, app_ep_i2a=ans_i2a)
    nvm = NVMeParser(addr=ANS_NVME_BAR, name="trace(ans_nvme)")

    for access in parsed_lines:
        if type(access) is not Access:
            print(access)
            continue

        if access.pa > ANS_MBOX and access.pa < (ANS_MBOX+0x1000):
            asc.access_asc(access)
        elif access.pa > ANS_NVME_BAR and access.pa < (ANS_NVME_BAR + 0x2000):
            nvm.access_nvm(access)
        else:
            print(access)

