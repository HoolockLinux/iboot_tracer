from parse import *
from akf import *
from construct import Adapter, Int64ul, Int32ul, Int16ul, Int8ul, ExprAdapter, GreedyRange, ListContainer, StopFieldError, ExplicitError, StreamError

def ans_i2a(asc: AKFParser, rel_ep: int, val):
    if rel_ep == 0:
        asc.print(f"ANS1 endpoint: {RTKMessage(val)}")
    else:
        asc.print(f"message {RTKMessage(val)} received from  unknown rel app endpoint {rel_ep}")
    return

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

    akf = AKFParser(addr=ANS_MBOX, name="trace(ans1)", app_ep_i2a=ans_i2a)

    for access in parsed_lines:
        if type(access) is not Access:
            print(access)
            continue

        if access.pa > ANS_MBOX and access.pa < (ANS_MBOX+0x1000):
            akf.access_akf(access)
        else:
            print(access)

