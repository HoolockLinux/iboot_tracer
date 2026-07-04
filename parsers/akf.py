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

#CPU_CONTROL = 0x28 (before mbox regs)
#mbox regs is +0x1000 or +0x4000

class MBoxRegs:
    A2I_CONTROL = 0x8

    A2I_SEND    = 0x10
    A2I_RECV    = 0x18
    A2I_SEND    = 0x10
    A2I_RECV    = 0x18

    I2A_CONTROL = 0x20

    I2A_SEND    = 0x30
    I2A_RECV    = 0x38

class RTKMessage(Register64):
    EP      = 63, 56

class ManagementMessage(RTKMessage):
    EP      = 63, 56, Constant(0)
    TYPE    = 55, 52

class Mgmt_Hello(ManagementMessage):
    EP      = 63, 56, Constant(0)
    TYPE    = 55, 52, Constant(1)
    MAX_VER = 31, 16
    MIN_VER = 15, 0

class Mgmt_HelloAck(ManagementMessage):
    EP      = 63, 56, Constant(0)
    TYPE    = 55, 52, Constant(2)
    MAX_VER = 31, 16
    MIN_VER = 15, 0

class Mgmt_Ping(ManagementMessage):
    EP      = 63, 56, Constant(0)
    TYPE    = 55, 52, Constant(3)

class Mgmt_Pong(ManagementMessage):
    EP      = 63, 56, Constant(0)
    TYPE    = 55, 52, Constant(4)

class Mgmt_StartEP(ManagementMessage):
    EP      = 63, 56, Constant(0)
    TYPE    = 55, 52, Constant(5)
    SEP     = 39, 32
    FLAG    = 1, 0

class Mgmt_SetIOPPower(ManagementMessage):
    EP      = 63, 56, Constant(0)
    TYPE    = 55, 52, Constant(6)
    STATE   = 15, 0

class Mgmt_IOPPowerAck(ManagementMessage):
    EP      = 63, 56, Constant(0)
    TYPE    = 55, 52, Constant(7)
    STATE   = 15, 0

class Mgmt_EPMap_Ack(ManagementMessage):
    EP       = 63, 56,
    TYPE     = 55, 52, Constant(8)
    LAST     = 51
    BASE     = 34, 32
    MAP_MORE = 31, 1 # 31-1: bitmap, 0: more

class Mgmt_EPMap(ManagementMessage):
    TYPE    = 56, 52, Constant(8)
    LAST    = 51
    BASE    = 34, 32
    BITMAP  = 31, 0

class Mgmt_SetAPPower(ManagementMessage):
    TYPE    = 59, 52, Constant(0xb)
    STATE   = 15, 0

class CrashLogMessage(RTKMessage):
    EP      = 63, 56, Constant(1)
    TYPE    = 55, 52

class Crash_BufferRequest(RTKMessage):
    EP      = 63, 56, Constant(1)
    TYPE    = 55, 52, Constant(1)
    SIZE    = 51, 44
    IOVA    = 41, 0 # for ack this is PA

class SysLogMessage(RTKMessage):
    EP      = 63, 56, Constant(2)
    TYPE    = 55, 52

class Sys_BufferRequest(RTKMessage):
    EP      = 63, 56, Constant(2)
    TYPE    = 55, 52, Constant(1)
    SIZE    = 51, 44
    IOVA    = 41, 0 # for ack this is PA

class Sys_Log(RTKMessage):
    EP      = 63, 56, Constant(2)
    TYPE    = 55, 52, Constant(5)
    INDEX   = 7, 0

class Sys_Init(RTKMessage):
    EP      = 63, 56, Constant(2)
    TYPE        = 55, 52, Constant(8)
    ENTRYSIZE   = 39, 24
    COUNT       = 15, 0

class AKFParser:
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
    app_ep_i2a: Callable[[AKFParser, int, int], None] | None
    app_ep_a2i: Callable[[AKFParser, int, int], None] | None
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

    def mailbox_I2A(self, val):
        if self.iop_power == RTKIT_POWET_STATE_OFF:
            self.iop_power = RTKIT_POWET_STATE_INIT
            self.print(f"rtkit IOP power state {RTKIT_POWET_STATE_OFF} -> {RTKIT_POWET_STATE_INIT}")

        msg = RTKMessage(val)
        match msg.EP:
            case 0: # RTKIT_EP_MGMT
                mgmt = ManagementMessage(val)
                match mgmt.TYPE:
                    case 1: # HELLO
                        hello = Mgmt_Hello(val)
                        if hello.MIN_VER > 10:
                            self.app_start = 0x20
                        else:
                            self.app_start = 0x6
                        self.print(f"mgmt hello: {Mgmt_Hello(val)}")
                    case 7:
                        self.print(f"mgmt iop_power_ack: {Mgmt_IOPPowerAck(val)}")
                    case 8: # Mgmt_EPMap
                        self.print(f"mgmt epmap_ack: {Mgmt_EPMap(val)}")
                    case 0xb: # Power
                        self.print(f"mgmt power_ack: {Mgmt_SetAPPower(val)}")
                    case _:
                        raise Exception(f"Not supported Mgmt I2A message: {msg}")
            case 1: # RTKIT_EP_CRASHLOG
                crash = CrashLogMessage(val)
                match crash.TYPE:
                    case 1:
                        self.print(f"crash_bfr: {Crash_BufferRequest(val)}")
                    case _:
                        raise Exception(f"Not supported Crashlog I2A message: {msg}")
            case 2: # RTKIT_EP_SYSLOG
                sys = SysLogMessage(val)
                match sys.TYPE:
                    case 1:
                        self.print(f"sys_bfr: {Sys_BufferRequest(val)}")
                    case 5:
                        self.print(f"sys_log: {Sys_Log(val)}")
                    case 8:
                        self.print(f"sys_init: {Sys_Init(val)}")
                    case _:
                        raise Exception(f"Not supported Syslog I2A message: {msg}")
            case _:
                ep = (val >> 56) & 0xff
                if (ep < self.app_start):
                    self.print(f"UNKNOWN ENDPOINT MESSAGE: {RTKMessage(val)}")
                elif self.app_ep_i2a is not None:
                    self.app_ep_i2a(self, ep - self.app_start, val)
                else:
                    self.print(f"A2I App endpoint rel {hex(ep - self.app_start)} message {RTKMessage(val)}")

    def mailbox_A2I(self, val):
        if self.iop_power == RTKIT_POWET_STATE_OFF:
            self.iop_power = RTKIT_POWET_STATE_INIT
            self.print(f"rtkit IOP power state {RTKIT_POWET_STATE_OFF} -> {RTKIT_POWET_STATE_INIT}")

        msg = RTKMessage(val)
        match msg.EP:
            case 0: # RTKIT_EP_MGMT
                mgmt = ManagementMessage(val)
                match mgmt.TYPE:
                    case 2: # HELLO_ACK
                        hello = Mgmt_HelloAck(val)
                        self.print(f"mgmt hello_ack: {Mgmt_HelloAck(val)}")
                    case 5: # MGMT_STAREP
                        self.print(f"mgmt startep:   {Mgmt_StartEP(val)}")
                    case 6:
                        self.print(f"mgmt iop_power: {Mgmt_SetIOPPower(val)}")
                    case 8: # Mgmt_EPMap_Ack
                        self.print(f"mgmt epmap_ack: {Mgmt_EPMap_Ack(val)}")
                    case 0xb: # power
                        self.print(f"mgmt power_ack: {Mgmt_SetAPPower(val)}")
                    case _:
                        raise Exception(f"Not supported Mgmt A2I message: {msg}")
            case 1: # RTKIT_EP_CRASHLOG
                crash = CrashLogMessage(val)
                match crash.TYPE:
                    case 1:
                        self.print(f"crash_bfr: {Crash_BufferRequest(val)}")
                    case _:
                        raise Exception(f"Not supported CrashLog A2I message: {msg}")
            case 2: # RTKIT_EP_SYSLOG
                sys = SysLogMessage(val)
                match sys.TYPE:
                    case 1:
                        self.print(f"sys_bfr: {Sys_BufferRequest(val)}")
                    case 5:
                        self.print(f"sys_log: {Sys_Log(val)}")
                    case _:
                        raise Exception(f"Not supported SysLog A2I message: {msg}")
            case _:
                ep = (val >> 56) & 0xff
                if (ep < self.app_start):
                    self.print(f"UNKNOWN ENDPOINT MESSAGE: {RTKMessage(val)}")
                elif self.app_ep_a2i is not None:
                    self.app_ep_a2i(self, ep - self.app_start, val)
                else:
                    self.print(f"I2A App endpoint rel {hex(ep - self.app_start)} message {RTKMessage(val)}")

    def read_access(self, access: Access):
        off = access.pa - self.addr
        match off:
            case MBoxRegs.I2A_RECV:
                if access.width != AccessWidth.W64:
                    self.print(f"UNSUPPORTED MAILBOX I2A_RECV {access}")
                self.mailbox_I2A(access.val)
            case MBoxRegs.A2I_CONTROL | MBoxRegs.I2A_CONTROL:
                pass # noise
            case _:
                self.print(f"Unknown mailbox reg {hex(off)} READ: {access}")

    def write_access(self, access: Access):
        off = access.pa - self.addr
        match off:
            case MBoxRegs.A2I_SEND:
                if access.width != AccessWidth.W64:
                    self.print(f"UNSUPPORTED MAILBOX A2I_SEND {access}")
                self.mailbox_A2I(access.val)
            case _:
                self.print(f"Unknown mailbox reg {hex(off)} WRITE: {access}")
    def access_akf(self, access: Access):
        if access.type == AccessType.READ:
            self.read_access(access)
        elif access.type == AccessType.WRITE:
            self.write_access(access)
