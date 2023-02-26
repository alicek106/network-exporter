# network-exporter (under development)

It exposes network sent/recv bytes per IP using cgroup ebpf.

```bash
root@alicek106-dev ~/github master*
❯ curl localhost:9000/metrics

# HELP network_bytes_recv Network Bytes Volume Received
# TYPE network_bytes_recv gauge
network_bytes_recv{source_ip="118.235.14.140"} 3256
# HELP network_bytes_sent Network Bytes Volume Sent
# TYPE network_bytes_sent gauge
network_bytes_sent{destination_ip="118.235.14.140"} 8328
network_bytes_sent{destination_ip="127.0.0.1"} 1410
network_bytes_sent{destination_ip="127.0.0.53"} 536
network_bytes_sent{destination_ip="172.31.0.2"} 335
network_bytes_sent{destination_ip="20.200.245.247"} 7344
```
