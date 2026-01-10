from __future__ import annotations
import sys
from enum import Enum
from parse import *
from typing import Callable
from construct import Adapter, Int64ul, Int32ul, Int16ul, Int8ul, ExprAdapter, GreedyRange, ListContainer, StopFieldError, ExplicitError, StreamError


RTKIT_POWET_STATE_OFF = 0x00
RTKIT_POWET_STATE_SLEEP = 0x01
RTKIT_POWET_STATE_QUIESCED = 0x10
RTKIT_POWET_STATE_ON = 0x20
RTKIT_POWET_STATE_INIT = 0x220

class MBoxRegs:
    UNK_100     = 0x100

    A2I_CONTROL = 0x108
    A2I_SEND0   = 0x800
    A2I_SEND1   = 0x808
    A2I_RECV0   = 0x810
    A2I_RECV1   = 0x818

    I2A_CONTROL = 0x10c
    I2A_SEND0   = 0x820
    I2A_SEND1   = 0x828
    I2A_RECV0   = 0x830
    I2A_RECV1   = 0x838

## Management endpoint
class ManagementMessage(Register64):
    TYPE    = 59, 52

class Mgmt_Hello(ManagementMessage):
    TYPE    = 59, 52, Constant(1)
    MAX_VER = 31, 16
    MIN_VER = 15, 0

class Mgmt_HelloAck(ManagementMessage):
    TYPE    = 59, 52, Constant(2)
    MAX_VER = 31, 16
    MIN_VER = 15, 0

class Mgmt_Ping(ManagementMessage):
    TYPE    = 59, 52, Constant(3)

class Mgmt_Pong(ManagementMessage):
    TYPE    = 59, 52, Constant(4)

class Mgmt_StartEP(ManagementMessage):
    TYPE    = 59, 52, Constant(5)
    EP      = 39, 32
    FLAG    = 1, 0

class Mgmt_SetIOPPower(ManagementMessage):
    TYPE    = 59, 52, Constant(6)
    STATE   = 15, 0

class Mgmt_IOPPowerAck(ManagementMessage):
    TYPE    = 59, 52, Constant(7)
    STATE   = 15, 0

class Mgmt_EPMap(ManagementMessage):
    TYPE    = 59, 52, Constant(8)
    LAST    = 51
    BASE    = 34, 32
    BITMAP  = 31, 0

class Mgmt_EPMap_Ack(ManagementMessage):
    TYPE    = 59, 52, Constant(8)
    LAST    = 51
    BASE    = 34, 32
    MORE    = 0

class Mgmt_SetAPPower(ManagementMessage):
    TYPE    = 59, 52, Constant(0xb)
    STATE   = 15, 0

class ASCMessage1(Register64):
    EP = 7, 0

# implement a Virtual ASC (kind of)
class ASCParser:
    addr: int
    iop_power: int
    ap_power: int
    app_start: int
    iop_min: int
    iop_max: int
    ap_min: int
    ap_max: int
    ver: int
    name: str
    app_ep_i2a: Callable[[ASCParser, int, int, int], None] | None
    app_ep_a2i: Callable[[ASCParser, int, int, int], None] | None
    def __init__(self, addr: int, name: str, app_ep_i2a=None, app_ep_a2i=None):
        self.addr = addr
        self.iop_power = RTKIT_POWET_STATE_OFF
        self.ap_power = RTKIT_POWET_STATE_OFF
        self.name = name
        self.app_start = 1 # RTKIT_EP_MGMT + 1
        self.app_ep_i2a = app_ep_i2a
        self.app_ep_a2i = app_ep_a2i

    def print(self, *values):
        print(f"{self.name}:", *values)
        pass

    def mailbox_I2A(self, val_lo, val_hi):
        if self.iop_power == RTKIT_POWET_STATE_OFF:
            self.iop_power = RTKIT_POWET_STATE_INIT
            self.print(f"rtkit IOP power state {RTKIT_POWET_STATE_OFF} -> {RTKIT_POWET_STATE_INIT}")

        msg0 = ManagementMessage(val_lo)
        msg1 = ASCMessage1(val_hi)

        # When not ON, only allow system messages
        if self.iop_power != 0x20 and int(f"{msg1.EP}") >= self.app_start:
            print(msg0, msg1)
            raise

        match msg1.EP:
            case 0: # RTKIT_EP_MGMT
                match msg0.TYPE:
                    case 1: # HELLO
                        hello = Mgmt_Hello(val_lo)
                        self.print(f"MGMT.HELLO: IOP supported versions {hello.MIN_VER}...{hello.MAX_VER}: {hello}, {msg1}")
                        self.iop_min = hello.MIN_VER
                        self.iop_max = hello.MAX_VER
                    case 2: # HELLO_ACK (unexpected)
                        self.print("unexpected MGMT.HELLO_ACK on I2A mailbox")
                        raise
                    case 5: # START_EP (unexpected)
                        self.print("unexpected MGMT.START_EP on I2A mailbox")
                        raise
                    case 6: # IOP_PWR_STATE (unexpected)
                        self.print("unexpected MGMT.IOP_PWR_STATE on I2A mailbox")
                        raise
                    case 7: # IOP_PWR_STATE_ACK
                        iop_pwr = Mgmt_IOPPowerAck(val_lo)
                        self.print(f"IOP Power state is now: {self.iop_power} -> {hex(iop_pwr.STATE)}: {iop_pwr}, {msg1}")
                        self.iop_power = iop_pwr.STATE
                    case 8: # MGMT_MSG_EPMAP_REPLY
                        ep_reply = Mgmt_EPMap_Ack(val_lo)
                        self.print(f"EPMAP reply (MORE->11+): {ep_reply}, {msg1}")

                    case 11: # MGMT_MSG_AP_PWR_STATE_ACK
                        ap_pwr = Mgmt_SetAPPower(val_lo)
                        self.print(f"IOP's AP Power state is now: {self.ap_power} -> {hex(ap_pwr.STATE)}: {ap_pwr}, {msg1}")
                        self.ap_power = ap_pwr.STATE
                    case _:
                        self.print(f"Unknown I2A management message type {msg0.TYPE} lo={hex(val_lo)}, hi={hex(val_hi)}")
            case 1: # RTKIT_EP_CRASHLOG
                self.print(f"I2A crashlog message lo={hex(val_lo)}, hi={hex(val_hi)}")
            case 2: # RTKIT_EP_SYSLOG
                self.print(f"I2A syslog message lo={hex(val_lo)}, hi={hex(val_hi)}")
            case 3: # RTKIT_EP_DEBUG
                self.print(f"I2A debug message lo={hex(val_lo)}, hi={hex(val_hi)}")
            case 4: # RTKIT_EP_IOREPORT
                self.print(f"I2A ioreport message lo={hex(val_lo)}, hi={hex(val_hi)}")
            case _:
                ver = min(self.ap_max, self.iop_max)
                if msg1.EP == 8 and ver > 10: # RTKIT_EP_OSLOG
                    self.print(f"I2A oslog message lo={hex(val_lo)}, hi={hex(val_hi)}")
                ep = int(f"{msg1.EP}")
                if ver < 11 and ep < 6:
                    self.print(f"Unknown I2A system endpoint {hex(ep)} message lo={hex(val_lo)}, hi={hex(val_hi)}")
                elif ver > 10 and ep < 20:
                    self.print(f"Unknown I2A system endpoint {hex(ep)} message lo={hex(val_lo)}, hi={hex(val_hi)}")
                elif self.app_ep_i2a is not None:
                    self.app_ep_i2a(self, ep - self.app_start, val_lo, val_hi)
                else:
                    self.print(f"I2A App endpoint rel {hex(ep - self.app_start)} message lo={hex(val_lo)}, hi={hex(val_hi)}")


    def mailbox_A2I(self, val_lo, val_hi):
        msg0 = ManagementMessage(val_lo)
        msg1 = ASCMessage1(val_hi)

        # When not ON, only allow system messages
        if self.iop_power != RTKIT_POWET_STATE_ON and int(f"{msg1.EP}") >= self.app_start:
            print(msg0, msg1)
            raise

        match msg1.EP:
            case 0: # RTKIT_EP_MGMT
                match msg0.TYPE:
                    case 1: # HELLO (unexpected)
                        self.print("unexpected MGMT.HELLO on A2I mailbox")
                        raise
                    case 2: # HELLO_ACK
                        hello = Mgmt_HelloAck(val_lo)
                        self.print(f"MGMT.HELLO_ACK: AP supported versions {hello.MIN_VER}...{hello.MAX_VER}: {hello}, {msg1}")
                        self.ap_min = hello.MIN_VER
                        self.ap_max = hello.MAX_VER
                        assert self.iop_max != 0
                        assert self.iop_min != 0
                        self.ver = min(self.ap_max, self.iop_max)
                        if self.ver < 11:
                            self.app_start = 6
                        elif self.ver > 10:
                            self.app_start = 0x20
                    case 5: # START_EP
                        ep_start = Mgmt_StartEP(val_lo)
                        self.print(f"Start endpoint: {ep_start} {msg1}")
                    case 6: # IOP_PWR_STATE
                        iop_pwr = Mgmt_SetIOPPower(val_lo)
                        self.print(f"Set IOP Power state: {iop_pwr}, {msg1}")
                    case 7: # IOP_PWR_STATE_ACK (unexpected)
                        self.print("Unexpected IOP_PWR_STATE_ACK on A2I mailbox")
                        raise
                    case 8: # MGMT_MSG_EPMAP
                        ep_reply = Mgmt_EPMap(val_lo)
                        self.print(f"EPMAP (MORE->11+): {ep_reply}, {msg1}")

                    case 11: # MGMT_MSG_AP_PWR_STATE
                        ap_pwr = Mgmt_SetAPPower(val_lo)
                        self.print(f"Set AP Power state: {ap_pwr}, {msg1}")
                    case _:
                        self.print(f"Unknown I2A management message type {msg0.TYPE} lo={hex(val_lo)}, hi={hex(val_hi)}")
            case 1: # RTKIT_EP_CRASHLOG
                self.print(f"A2I crashlog message lo={hex(val_lo)}, hi={hex(val_hi)}")
            case 2: # RTKIT_EP_SYSLOG
                self.print(f"A2I syslog message lo={hex(val_lo)}, hi={hex(val_hi)}")
            case 3: # RTKIT_EP_DEBUG
                self.print(f"A2I debug message lo={hex(val_lo)}, hi={hex(val_hi)}")
            case 4: # RTKIT_EP_IOREPORT
                self.print(f"A2I ioreport message lo={hex(val_lo)}, hi={hex(val_hi)}")
            case _:
                ver = min(self.ap_max, self.iop_max)
                if msg1.EP == 8 and ver > 10: # RTKIT_EP_OSLOG
                    self.print(f"A2I oslog message lo={hex(val_lo)}, hi={hex(val_hi)}")
                ep = int(f"{msg1.EP}")
                if ver < 11 and ep < 6:
                    self.print(f"Unknown A2I system endpoint {hex(ep)} message lo={hex(val_lo)}, hi={hex(val_hi)}")
                elif ver > 10 and ep < 20:
                    self.print(f"Unknown A2I system endpoint {hex(ep)} message lo={hex(val_lo)}, hi={hex(val_hi)}")
                elif self.app_ep_a2i is not None:
                    self.app_ep_a2i(self, ep - self.app_start, val_lo, val_hi)
                else:
                    self.print(f"A2I App endpoint rel {hex(ep - self.app_start)} message lo={hex(val_lo)}, hi={hex(val_hi)}")
    
    def read_access(self, access: Access):
        off = access.pa - self.addr
        match off:
            case MBoxRegs.UNK_100 | MBoxRegs.I2A_SEND0 | MBoxRegs.I2A_SEND1 | MBoxRegs.A2I_RECV0 | MBoxRegs.A2I_RECV1 | MBoxRegs.A2I_SEND0 | MBoxRegs.A2I_SEND1 | MBoxRegs.I2A_RECV1:
                self.print(f"Unsupported mailbox reg {hex(off)} READ: {access}")
                return
            case MBoxRegs.A2I_CONTROL:
                if access.width != AccessWidth.W32:
                    self.print("Unsupported mailbox A2I_CONTROL reg READ: {access}")
                    return
                # mostly just noise for trace purposes
                #self.print(f"READ A2I_CONTROL {hex(access.val)}")
            case MBoxRegs.I2A_CONTROL:
                if access.width != AccessWidth.W32:
                    self.print("Unsupported mailbox I2A_CONTROL reg READ: {access}")
                    return
                # mostly just noise for trace purposes

                #self.print(f"READ I2A_CONTROL {hex(access.val)}")
            # iboot seems to only do 16-byte access for send receive
            # so is this okay?
            case MBoxRegs.I2A_RECV0:
                if access.width != AccessWidth.W128:
                    self.print("Unsupported mailbox I2A_RECV0 reg READ: {access}")
                    return
                assert access.val_hi is not None
                #self.print(f"READ I2A_RECV lo={hex(access.val)} hi={hex(access.val_hi)}")
                self.mailbox_I2A(access.val, access.val_hi)
            case _:
                self.print(f"Unknown mailbox reg {hex(off)} READ: {access}")

        return
    def write_access(self, access: Access):
        off = access.pa - self.addr
        match off:
            case MBoxRegs.I2A_SEND0 | MBoxRegs.I2A_SEND1 | MBoxRegs.A2I_RECV0 | MBoxRegs.A2I_RECV1 | MBoxRegs.A2I_SEND1 | MBoxRegs.I2A_RECV0 | MBoxRegs.I2A_RECV1:
                self.print(f"Unsupported mailbox reg {hex(off)} WRITE: {access}")
                return
            case MBoxRegs.UNK_100:
                if access.width != AccessWidth.W32:
                    self.print(f"Unsupported mailbox UNK_100 reg WRITE: {access}")
                    return
                self.print(f"WRITE UNK_100 {hex(access.val)}")
            case MBoxRegs.A2I_CONTROL:
                if access.width != AccessWidth.W32:
                    self.print(f"Unsupported mailbox A2I_CONTROL reg WRITE: {access}")
                    return
                self.print(f"WRITE A2I_CONTROL {hex(access.val)}")
            case MBoxRegs.I2A_CONTROL:
                if access.width != AccessWidth.W32:
                    self.print(f"Unsupported mailbox I2A_CONTROL reg WRITE: {access}")
                    return
                self.print(f"WRITE I2A_CONTROL {hex(access.val)}")
            # iboot seems to only do 16-byte access for send receive
            # so is this okay?
            case MBoxRegs.A2I_SEND0:
                if access.width != AccessWidth.W128:
                    self.print(f"Unsupported mailbox I2A_SEND0 reg WRITE: {access}")
                    return
                assert access.val_hi is not None
                #self.print(f"WRITE A2I_SEND lo={hex(access.val)} hi={hex(access.val_hi)}")
                self.mailbox_A2I(access.val, access.val_hi)
            case _:
                self.print(f"Unknown mailbox reg {hex(off)} WRITE: {access}")

        return
    def access_asc(self, access: Access):
        if access.type == AccessType.READ:
            self.read_access(access)
        elif access.type == AccessType.WRITE:
            self.write_access(access)

    #def read_reg(self, addr: int, val: int, width: AccessWidth):
    #    pass

    #def write_reg(self, addr: int, val: int, width: AccessWidth):
    #    pass
