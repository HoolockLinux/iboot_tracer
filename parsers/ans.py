from parse import *
from asc import *
from construct import Adapter, Int64ul, Int32ul, Int16ul, Int8ul, ExprAdapter, GreedyRange, ListContainer, StopFieldError, ExplicitError, StreamError

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

    for access in parsed_lines:
        if type(access) is not Access:
            print(access)
            continue

        if access.pa > ANS_MBOX and access.pa < (ANS_MBOX+0x1000):
            asc.access_asc(access)
        else:
            print(access)

