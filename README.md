# Build

## Build cmd binary locally

You can build the locally by executing

```bash
go build ./...
```

## Build Docker container

You can build the docker container by running:

```bash
docker build .
```

# Usage

## Environment config

* `NSM_NAME`                             - Name of Endpoint
* `NSM_LABELS`                           - Labels related to this forwarder-vpp instance
* `NSM_NSNAME`                           - Name of Network Service to Register with Registry
* `NSM_CONNECT_TO`                       - url to connect to
* `NSM_LISTEN_ON`                        - url to listen on
* `NSM_MAX_TOKEN_LIFETIME`               - maximum lifetime of tokens
* `NSM_REGISTRY_CLIENT_POLICIES`         - paths to files and directories that contain registry client policies
* `NSM_LOG_LEVEL`                        - Log level
* `NSM_DIAL_TIMEOUT`                     - Timeout for the dial the next endpoint
* `NSM_OPEN_TELEMETRY_ENDPOINT`          - OpenTelemetry Collector Endpoint
* `NSM_METRICS_EXPORT_INTERVAL`          - interval between mertics exports
* `NSM_PPROF_ENABLED`                    - is pprof enabled (default: "false")
* `NSM_PPROF_LISTEN_ON`                  - pprof URL to ListenAndServe (default: "localhost:6060")
* `NSM_PROMETHEUS_LISTEN_ON`             - Prometheus URL to ListenAndServe (default: ":8081")
* `NSM_PROMETHEUS_CERT_FILE`             - path to the certificate file for the Prometheus server
* `NSM_PROMETHEUS_KEY_FILE`              - path to the key file for the Prometheus server
* `NSM_PROMETHEUS_CA_FILE`               - path to the CA file for the Prometheus server
* `NSM_PROMETHEUS_MONITOR_CERTIFICATE`   - defines whether the custom certificate for Prometheus should be monitored (default: "false")
* `NSM_PROMETHEUS_SERVER_HEADER_TIMEOUT` - sets the header timeout for the Prometheus metrics server (default: "5s")
* `NSM_PROMETHEUS_MAX_BIND_THRESHOLD`    - Timeout for how long the Prometheus server will try to bind to the same address before giving up (default: "120s")
* `NSM_TUNNEL_IP`                        - IP to use for tunnels
* `NSM_VXLAN_PORT`                       - VXLAN port to use
* `NSM_VPP_API_SOCKET`                   - filename of socket to connect to existing VPP instance.
* `NSM_VPP_INIT`                         - type of VPP initialization. Must be AF_XDP, AF_PACKET or NONE
* `NSM_VPP_INIT_PARAMS`                  - Configuration file path containing VPP API parameters for initialization
* `NSM_VPP_MIN_OPERATION_TIMEOUT`        - minimum timeout for every vpp operation
* `NSM_RESOURCE_POLL_TIMEOUT`            - device plugin polling timeout
* `NSM_DEVICE_PLUGIN_PATH`               - path to the device plugin directory
* `NSM_POD_RESOURCES_PATH`               - path to the pod resources directory
* `NSM_DEVICE_SELECTOR_FILE`             - config file for device name to label matching
* `NSM_SRIOV_CONFIG_FILE`                - PCI resources config path
* `NSM_PCI_DEVICES_PATH`                 - path to the PCI devices directory
* `NSM_PCI_DRIVERS_PATH`                 - path to the PCI drivers directory
* `NSM_CGROUP_PATH`                      - path to the host cgroup directory
* `NSM_VFIO_PATH`                        - path to the host VFIO directory
* `NSM_MECHANISM_PRIORITY`               - sets priorities for mechanisms

# Testing

## Testing Docker container

Testing is run via a Docker container.  To run testing run:

```bash
docker run --privileged --rm $(docker build -q --target test .)
```

# Debugging

## Debugging the tests
If you wish to debug the test code itself, that can be acheived by running:

```bash
docker run --privileged --rm -p 40000:40000 $(docker build -q --target debug .)
```

This will result in the tests running under dlv.  Connecting your debugger to localhost:40000 will allow you to debug.

```bash
-p 40000:40000
```
forwards port 40000 in the container to localhost:40000 where you can attach with your debugger.

```bash
--target debug
```

Runs the debug target, which is just like the test target, but starts tests with dlv listening on port 40000 inside the container.

## Debugging the cmd

When you run 'cmd' you will see an early line of output that tells you:

```Setting env variable DLV_LISTEN_FORWARDER to a valid dlv '--listen' value will cause the dlv debugger to execute this binary and listen as directed.```

If you follow those instructions when running the Docker container:
```bash
docker run --privileged -e DLV_LISTEN_FORWARDER=:50000 -p 50000:50000 --rm $(docker build -q --target test .)
```

```-e DLV_LISTEN_FORWARDER=:50000``` tells docker to set the environment variable DLV_LISTEN_FORWARDER to :50000 telling
dlv to listen on port 50000.

```-p 50000:50000``` tells docker to forward port 50000 in the container to port 50000 in the host.  From there, you can
just connect dlv using your favorite IDE and debug cmd.

## Debugging the tests and the cmd

```bash
docker run --privileged -e DLV_LISTEN_FORWARDER=:50000 -p 40000:40000 -p 50000:50000 --rm $(docker build -q --target debug .)
```

Please note, the tests **start** the cmd, so until you connect to port 40000 with your debugger and walk the tests
through to the point of running cmd, you will not be able to attach a debugger on port 50000 to the cmd.

## A Note on Running golangci-lint

Because cmd-forwarder-vpp is only anticipated to run in Linux, you will need to run golangci-lint run with:

```go
GOOS=linux golangci-lint run
```
