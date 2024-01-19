# PATAT Library

This project implements a Rust library for using PATAT (Protocol for ATtestion
in Arm TrustZone).

## Podman setup

``` shell
podman run -v $PWD:/optee/optee_rust/examples/patat-protocol-rs:z --name qemu-optee -it qemu-optee:latest bash
```


Run the following to start the `main` shell.
```shell
docker build -f Dockerfile -t qemu-optee .
docker create -v $PWD:/optee/optee_rust/examples/patat-protocol-rs:z --name qemu-optee --network host -it qemu-optee:latest bash
docker start -i qemu-optee
```

Then in 2 other shells do:
```shell
docker exec -it qemu-optee ./soc_term.py 54321
docker exec -it qemu-optee ./soc_term.py 54320
```

Now you can build the code in the `main` shell with the following command:

```shell
make toolchains && make OPTEE_RUST_ENABLE=y CFG_TEE_RAM_VA_SIZE=0x00300000
```

And running it is:

```shell
make run-only
```

After it started, press `c` in the `main` shell. Then you will see the other
2 shells booting up. In the "regular" shell, type `test` to login. In the
Trusted World shell, you only see some printed lines for now.


