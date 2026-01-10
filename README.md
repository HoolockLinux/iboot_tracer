# iBoot Tracer

Hack iBoot data abort handler and corrupt its pagetables
to trace its MMIO access. Supports T8010, T8011, T8012,
T8015 and is designed for iOS 15 iBoots.

## Building

Building is supported on macOS and Linux. clang must be used.

You must use a sufficiently recent version of GNU Make, and not a
2006 GNU Make.

On Linux, building is supported with [cctools-port](https://github.com/tpoechtrager/cctools-port).
The makefiles assume that the tools are prefixed with `cctools-`.
You can override them with `LD_FOR_TARGET` and `OTOOL` variables.

## iBoot selection

The code is placed between iBoot's text end and aligned text end,
so iBoot must itself be sufficiently misaligned for the code to work.
At least one of 15.0 or 15.4 iBoots should work.

## Tracing

Create `shellcode/src/trace_config.h` to control which addresses where
load/store will be emulated. The addresses must be aligned to L2 entry
size.

Use `TRACE_CONFIG_FLAG_FAULT` to trace with translation fault (slow),
otherwise tracer will use no-unprivileged-access to trace (only works
for EL0).

Since L2 entry size is quite large, you must specify a whitelist of
addresses that will actually be traced.

example:

```c
#ifndef TRACE_CONFIG_H
#define TRACE_CONFIG_H

#include "common.h"

// Specify bit [35:25] of the address to trace as bit [15:4]
// This will cause access to 0x20a000000 - 0x20c000000,
// 0x600000000 - 0x602000000 to be emulated.
static const u16 trace_config[] = {
    0x20a0 | TRACE_CONFIG_FLAG_FAULT, // I2C
    0x6000, // PCIE
};

// Specify which addresses where access is actually printed.
// Specify bit [35:4] of the start of the whitelist as bit [31:0]
// Second member is the size
// Combined with the above this casues accesses to
// 0x20a110000 - 0x20a111000, 0x600000000 - 0x602000000 to actually
// be printed.
static const struct whitelist_range whitelist_addr[] = {
    {0x20a11000, 0x1000}, // I2C0
    {0x60000000, 0x2000000}, // PCIE
};

#endif
```

## Trace output format

All numbers are in hexadecimal.

### 1, 2, 4, 8 byte(s)

```
pc:access_type virt@phys=value-width_shift
```

- `access_type` may be `R` (read) or `W` (write).
- `value` is the value to be read or written.
- The width of the access is a `1 << width_shift`

example:

```
180025b1c:W 236024000@236024000=74280-2
```

- pc is at `0x180025b1c`
- This is a write
- virtual address of the access is `0x236024000`
- physical address of the access is `0x236024000`
- The value `0x74280` is written
- The size of the access is `1 << 2` = 4 bytes

### 16 bytes

```
pc:access_type virt_lo@phys_lo=value_lo-width_shift|virt_hi@phys_hi=value_hi=width_shift
```

- `access_type` may be `R` (read) or `W` (write).
- `value_lo` and `value_hi` is the lower and upper 8 bytes of the value to be read or written
- The width of the access is a `1 << width_shift` (always 16)

example:

```
1800573f0:R 236808830@236808830=2300004c000-4|236808838@236808838=10560000000020-4
```

- pc is at `0x1800573f0`
- This is a read
- virtual address of the access is `0x236808830`
- physical address of the access is `0x236808830`
- the value `0x2300004c000` is read from the lower 8 bytes
- the value `0x10560000000020` is read from the upper 8 bytes
- the size of the access is `1 << 4` = 16 bytes

## License

ibootpatch3 is licensed under the MIT license, as included in the [LICENSE](./LICENSE) file.

The load-store emulator and parts of the python scripts in `parsers` are taken from
[m1n1](https://github.com/AsahiLinux/m1n1), which is licened under the MIT license.

- Copyright The Asahi Linux Contributors

Plooshfinder is used, which is licensed under GNU Lesser General Public License v3.0.

This project is an iBoot patcher that also links code into iBoot which is (c) Apple, Inc.. The
acceptability of this practice depends on the jurisdiction. Please check your local laws.
