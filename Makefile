all: build

build:
	clang -g -Wall -Werror -O2 -emit-llvm  -c cgroup_skb.c -o - | llc -march=bpf -filetype=obj -o cgroup_skb.o
	go build -o app
