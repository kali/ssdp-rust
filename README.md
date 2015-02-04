# ssdp-rust
Rust library for SSDP

This is work in progress and NOT USABLE right now.

Even if the discovery code is kinda working, **rust currently does not allow to bind reusable udp socket**.

So if any other app is already running, it will not start. If it is the first to start, it will ruin the SSDP port for every other process.

As soon as reusable sockets are available (it will be in the rust io), I'll make it work.
