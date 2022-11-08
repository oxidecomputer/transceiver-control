# Host-to-SP management of network transceivers

This workspace allows managing the optical transceivers on a Sidecar from the
host. It provides a network protocol and a host-side control interface for
making requests of the Service Processor (SP), which in turn uses the I2C
interface that QSFP modules implement to control and monitor the transceivers.

## Crates

- `transceiver-messages`: A `no_std` crate defining the network protocol for
  communicating between host and SP.
- `transceiver-controller`: A crate used on the host side, operating as the
  controller of a set of transceivers via the SP.
