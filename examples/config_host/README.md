# C configuration host

This console host uses only `<solaris/core.h>` and the C11 standard library. It
loads a YAML file, starts the runtime, prepares all resources and commits the
configuration before reporting `ready`. It does not change system proxy settings,
routes, DNS or TUN devices. The supplied YAML listens only on loopback.

Build the installed example directory with the relocated SDK prefix:

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH=/path/to/solaris-sdk
cmake --build build
./build/solaris_config_host config_host.yaml --ephemeral
```

On Windows, use the configuration subdirectory if needed and put the SDK `bin`
directory on `PATH`. No repository checkout or internal headers are required.

`--ephemeral` explicitly overrides the enabled listeners to ephemeral ports;
reported metadata includes the configured, requested and actual ports. Without
it, the supplied sample uses ports 7890 and 7891. YAML port zero still means a
disabled listener. `--workers N` selects 1–32 I/O workers. `--trust CA.pem` supplies
explicit trust for configured TLS proxies and HTTPS probes; there is no implicit
system-trust lookup. `--check` performs offline compilation only, without proving
that trust material or listener resources can be prepared.

Commands are read from standard input; paths and names can be quoted. Each command
prints one JSON result. Examples:

```text
nodes
status
select Route DIRECT
mode rule
probe DIRECT http://127.0.0.1:8080/health 3000
connections
traffic
logs
load config_host_reload.yaml
close all
stop
start
quit
```

Use `close GENERATION ID` for one connection. Read log pages with `logs CURSOR`.
A failed `load` keeps the active configuration and the saved restart filename.
`start` reapplies that file after a stop. Existing TCP/UDP connections retain their
original plan across successful updates.

Commands are serialized on the console thread for clarity. SDK callbacks only
copy results; the host waits for the operation and callback barrier before
reusing their storage. A host-side wait timeout requests cancellation and still
drains the operation before releasing its callback context. EOF and `quit` both
stop and destroy the engine before the host releases its state.
