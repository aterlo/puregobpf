PureGoBpf is a all Go implementation for interacting with some of the Linux kernel's eBPF features. So far, PureGoBpf is focused on cls_bpf use cases so if you want to use it for other eBPF use cases there will be work to do. However, the map implementation is generic so it should work for other use cases.

You may also want to take a look at the GoBpf (https://github.com/iovisor/gobpf) project for another approach to interacting with eBPF that uses C Go.

# Testing

Root permissions are required to run the tests because the tests load eBPF programs.

`ulimit -l unlimited`
`go test`
