# Transceiver controller

Library and CLI for managing Sidecar front IO optical transceivers.

## Overview

The Sidecar front IO ports are designed to support active optical transceiver
modules. There are a number of different standards which all support the same
form factor, usually called SFP or QSFP, for (Quad) Small Form-factor Pluggable
modules.

These modules are generally pretty complex and power-hungry (being active
optical), and thus require a good deal of management by switch software. The
Tofino ASIC driver, generally referred to as the Barefoot Software Developement
Environment (BF SDE) expects to manage these ports, so that it can correctly
walk them through its internal state machines (bringing ports up / down, setting
speeds according to the devices in each port, etc.). However, the SDE needs to
be told how to actually do that on a given "platform" with a Tofino, in this
case, Sidecar. We do that by way of a network protocol communicating between the
host (the Dendrite binary `dpd`) and the Sidecar SP. That SP talks to the
transceivers on the front IO board directly, in response to requests from the
host.

This crate defines a library interface and a command-line tool for talking to
the SP. The library is consumed by the CLI, and will be used to implement the
platform support the BF SDE expects of us.

## `xcvradm`

The main binary of this crate is `xcvradm`. Its synopsis is:

```bash
$ $ ./xcvradm
Administer optical network transceiver modules

Usage: xcvradm [OPTIONS] --interface <INTERFACE> <COMMAND>

Commands:
  status            Return the status of the addressed modules, such as presence, power enable, and power mode
  reset             Reset the addressed modules
  set-power         Set the power module of the addressed modules
  power             Return the power mode of the addressed modules
  enable-power      Enable the hot swap controller for the addressed modules
  disable-power     Disable the hot swap controller for the addressed modules
  assert-reset      Assert ResetL for the addressed modules
  deassert-reset    Deassert ResetL for the addressed modules
  assert-lp-mode    Assert LpMode for the addressed modules
  deassert-lp-mode  Deassert LpMode for the addressed modules
  identify          Read the SFF-8024 identifier for a set of modules
  vendor-info       Read the vendor information for a set of modules
  read-lower        Read the lower page of a set of transceiver modules
  write-lower       Write the lower page of a set of transceiver modules
  read-upper        Read data from an upper memory page
  write-upper       Write the upper page of a set of transceiver modules
  memory-model      Describe the memory model of a set of modules
  macs              Return the MAC addresses for the particular system allotted by its FRUID
  help              Print this message or the help of the given subcommand(s)

Options:
  -t, --transceivers <TRANSCEIVERS>
          The list of transcievers on the FPGA to address
  -a, --address <ADDRESS>
          The source IP address on which to listen for messages [default: ::]
  -i, --interface <INTERFACE>
          The source interface on which to listen for messages
  -P, --port <PORT>
          The source UDP port from which to send messages [default: 0]
  -p, --peer <PEER>
          The unicast peer address to assume
      --peer-port <PEER_PORT>
          The destination UDP port to which to send messages [default: 11112]
  -n, --n-retries <N_RETRIES>
          The maximum number of retries before failing a request
  -r, --retry-interval <RETRY_INTERVAL>
          The retry interval for requests, in milliseconds [default: 1000]
  -l, --log-level <LOG_LEVEL>
          The log-level [default: INFO]
  -h, --help
          Print help information (use `--help` for more detail)
  -V, --version
          Print version information
```

The required option `--interface` is used to specify the IP interface through
which the SP is reachable. The other common option is `--transceivers`, which is
a list of the actual transceivers on the Sidecar to address.

### `status`

The first command to run is `xcvradm status`. You should see something like:

```bash
$ ./xcvradm -i axf0 status
Port Status
   0 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   2 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   3 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   4 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   5 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   6 RESET | LOW_POWER_MODE
   7 RESET | LOW_POWER_MODE
   8 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   9 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
  10 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
  11 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
  12 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
  13 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
  14 RESET | LOW_POWER_MODE
  15 RESET | LOW_POWER_MODE
```

That shows the bitmask of the state for each transceiver. In this case, a few
have nothing plugged into them, but the rest are present and enabled in
low-power mode.

### `identify`

There are a bunch of kinds of devices that all sport the same form factor, but
the most common are QSFP+ / QSFP-28 and QSFP-DD. These are referred to in
`xcvradm` by the specification that governs their mangement interface, SFF-8636
and CMIS respectively. You can see these kinds of details along with the vendor
information by using `xcvradm identify`:

```bash
$ ./xcvradm -i axf0 -t3,4 identify
Port Identifier           Vendor           Part             Rev  Serial           Mfg date
   3 QsfpPlusCmis (0x1e)  FINISAR CORP.    FTCC8612E1PCM    A0   X4MAG53          05 Feb 2021 (Lot )
   4 Qsfp28 (0x11)        Intel Corp       SPTMBP1PACDF010  01   LTAC2007001GS    12 Feb 2020
```

### Power modes and resetting

You can set modules into various power modes with `xcvradm set-power`:

```bash
$ ./xcvradm -i axf0 -t3 status
Port Status
   3 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
$ ./xcvradm -i axf0 -t3 set-power off
$ ./xcvradm -i axf0 -t3 status
Port Status
   3 PRESENT | RESET | LOW_POWER_MODE
$ ./xcvradm -i axf0 -t3 set-power low
$ ./xcvradm -i axf0 -t3 status
Port Status
   3 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
```

Modules can be reset with `xcvradm reset`.

### Reading / writing data

You can read and write the memory maps for the transceivers using `xcvradm
{read-lower,read-upper,write-lower,write-upper}`. This requires understanding a
good bit of detail about the devices, as the meaning of each byte and the
upper/lower memory split is entirely module-specific. Read SFF-8636 and CMIS 5.0
if you need to use these.

### Errors

All of the operations in `xcvradm` are fallible. Modules may be pulled at any
point or power may fail, or they may fail for any number of other reasons. This
is compounded by the fact that commands address _multiple_ modules. We'd like to
receive valid data, or follow through an operation where we can, and also report
the failures we encounter.

As an example, suppose we want to read the vendor information from two modules,
and one of those fails. `xcvradm` will print the successfully read information
from one module on the standard output. After all successes are reported,
information about the modules which failed and the cause for each, on the
standard error stream.
