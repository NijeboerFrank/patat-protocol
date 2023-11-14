# PATAT Library

This project implements a Rust library for using PATAT (Protocol for ATtestion
in Arm TrustZone).

## Podman setup

``` shell
podman run -v $PWD:/optee/optee_rust/examples/patat-protocol-rs:z --name qemu-optee -it qemu-optee:latest bash
```

