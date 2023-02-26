package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func intToIP(val uint32) net.IP {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], val)
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
}

func ipToInt(val string) uint32 {
	ip := net.ParseIP(val).To4()
	return binary.LittleEndian.Uint32(ip)
}

// In general, cgorupv2 attach path is /sys/fs/cgroup
const DEFAULT_CGROUP2_PATH = "/sys/fs/cgroup"

var networkBytesRecv = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "network_bytes_recv",
		Help: "Network Bytes Volume Received",
	},
	[]string{"source_ip"},
)

var networkBytesSent = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "network_bytes_sent",
		Help: "Network Bytes Volume Sent",
	},
	[]string{"destination_ip"},
)

func init() {
}

func main() {
	collec, err := ebpf.LoadCollection("./cgroup_skb.o")
	if err != nil {
		log.Fatalf("failed to load object collection: %v", err)
	}

	ingress_link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    DEFAULT_CGROUP2_PATH,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: collec.Programs["count_ingress_packets_func"],
	})
	if err != nil {
		log.Fatalf("failed to attach ingress link: %v", err)
	}
	defer ingress_link.Close()

	egress_link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    DEFAULT_CGROUP2_PATH,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: collec.Programs["count_egress_packets_func"],
	})
	if err != nil {
		log.Fatalf("failed to attach egress link: %v", err)
	}
	defer egress_link.Close()

	ingress_bpf_map := collec.Maps["count_ingress_packets"]
	egress_bpf_map := collec.Maps["count_egress_packets"]

	ticker := time.NewTicker(1 * time.Second)
	var key uint32
	var value uint64

	go func() {
		pr := prometheus.NewRegistry()
		pr.MustRegister(networkBytesRecv)
		pr.MustRegister(networkBytesSent)
		handler := promhttp.HandlerFor(pr, promhttp.HandlerOpts{})
		r := mux.NewRouter()
		srv := &http.Server{
			Addr:         ":9000",
			WriteTimeout: time.Second * 15,
			ReadTimeout:  time.Second * 15,
			IdleTimeout:  time.Second * 15,
			Handler:      r,
		}
		r.Handle("/metrics", handler)
		fmt.Println("Listening on :9000")

		if err := srv.ListenAndServe(); err != nil {
			panic(err)
		}
	}()

	for range ticker.C {
		entries := egress_bpf_map.Iterate()
		for entries.Next(&key, &value) {
			// fmt.Printf("key: %s, value: %d\n", intToIP(key).String(), value)
			networkBytesSent.WithLabelValues(intToIP(key).String()).Set(float64(value))
		}

		entries = ingress_bpf_map.Iterate()
		for entries.Next(&key, &value) {
			// fmt.Printf("key: %s, value: %d\n", intToIP(key).String(), value)
			networkBytesRecv.WithLabelValues(intToIP(key).String()).Set(float64(value))
		}
	}

}
