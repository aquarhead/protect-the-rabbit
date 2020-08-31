# Protect the Rabbit!

L7 policies for RabbitMQ, powered by [BPF](https://ebpf.io/).

## Limit consumers per connection

Currently hard coded to 10 consumers, try with:

```
# compile
cargo make bpf

# Add queue
sudo tc qdisc add dev lo clsact

# Enable BPF
sudo tc filter add dev lo ingress \
  bpf da obj target/bpf/programs/limit/limit.elf sec tc_action/limit

# Cleanup
# sudo tc filter del dev lo ingress
```

Change `lo` to desired network device (can be listed from `ip link`).

## References / Useful Links

- https://blogs.oracle.com/linux/notes-on-bpf-1 discussed different program types, especially cleared confusion around socket filter (why it doesn't work for this use case)
- https://docs.cilium.io/en/v1.8/bpf/# especially `tc` related sections
- https://man7.org/linux/man-pages/man8/tc-bpf.8.html
- https://tldp.org/HOWTO/Traffic-Control-HOWTO/components.html explains some terminologies
- https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf see "AMQP Wire-Level Format"
- https://www.rabbitmq.com/amqp-wireshark.html
- https://www.rabbitmq.com/amqp-0-9-1-reference.html hover over methods to see IDs, lol
- C examples:
  - https://git.kernel.org/pub/scm/network/iproute2/iproute2-next.git/tree/examples/bpf
  - https://github.com/iovisor/bcc/blob/master/examples/networking/http_filter/http-parse-complete.c
