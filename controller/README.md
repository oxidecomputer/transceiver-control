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
  status        Return the status of the addressed modules, such as presence, power enable, and power mode
  reset         Reset the addressed modules
  set-power     Set the power module of the addressed modules
  identify      Extract the identity information for a set of modules
  read-lower    Read the lower page of a set of transceiver modules
  write-lower   Write the lower page of a set of transceiver modules
  read-upper    Read data from an upper memory page
  write-upper   Write the upper page of a set of transceiver modules
  memory-model  Describe the memory model of a set of modules
  help          Print this message or the help of the given subcommand(s)

Options:
  -f, --fpga-id <FPGA_ID>
          The FPGA whose transceivers to address [default: 0]
  -t, --transceivers <TRANSCEIVERS>
          The comma-separated list of transcievers on the FPGA to address
  -a, --address <ADDRESS>
          The source IP address on which to listen for messages [default: ::]
  -i, --interface <INTERFACE>
          The source interface on which to listen for messages
  -p, --peer <PEER>
          The unicast peer address to assume
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
which the SP is reachable. The other common options are `--fpga` which specifies
the FPGA whose transceivers are addressed, and `--transceivers`, which is a list
of the actual transceivers on that FPGA to operate on.

### `status`

The first command to run is `xcvradm status`. You should see something like:

```bash
$ ./xcvradm -i axf0 -f1 status
FPGA Port Status
   1    0 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1    1 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1    2 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1    3 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1    4 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1    5 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1    6 RESET | LOW_POWER_MODE
   1    7 RESET | LOW_POWER_MODE
   1    8 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1    9 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1   10 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1   11 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1   12 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1   13 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
   1   14 RESET | LOW_POWER_MODE
   1   15 RESET | LOW_POWER_MODE
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
$ ./xcvradm -i axf0 -f1 -t3,4 identify
FPGA Port Identifier           Vendor           Part             Rev  Serial           Mfg date
   1    3 QsfpPlusCmis (0x1e)  FINISAR CORP.    FTCC8612E1PCM    A0   X4MAG53          05 Feb 2021 (Lot )
   1    4 Qsfp28 (0x11)        Intel Corp       SPTMBP1PACDF010  01   LTAC2007001GS    12 Feb 2020
```

### Power modes and resetting

You can set modules into various power modes with `xcvradm set-power`:

```bash
$ ./xcvradm -i axf0 -f1 -t3 status
FPGA Port Status
   1    3 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
$ ./xcvradm -i axf0 -f1 -t3 set-power off
$ ./xcvradm -i axf0 -f1 -t3 status
FPGA Port Status
   1    3 PRESENT | RESET | LOW_POWER_MODE
$ ./xcvradm -i axf0 -f1 -t3 set-power low
$ ./xcvradm -i axf0 -f1 -t3 status
FPGA Port Status
   1    3 PRESENT | ENABLED | LOW_POWER_MODE | INTERRUPT
```

Modules can be reset with `xcvradm reset`.

### Reading / writing data

You can read and write the memory maps for the transceivers using `xcvradm
{read-lower,read-upper,write-lower,write-upper}`. This requires understanding a
good bit of detail about the devices, as the meaning of each byte and the
upper/lower memory split is entirely module-specific. Read SFF-8636 and CMIS 5.0
if you need to use these.
