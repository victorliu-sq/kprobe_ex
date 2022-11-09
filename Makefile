ARCH=$(shell uname -m)

LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := /usr/lib/$(ARCH)-linux-gnu/libbpf.a

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"

all: vmlinux.h bpf_target go_target

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_target: simple.bpf.c
	clang -g -O2 -c -target bpf -o simple.bpf.o simple.bpf.c

go_target: simple.bpf.o main.go
	$(go_env) go build -o libbpfgo-prog

clean:
	rm simple.bpf.o libbpfgo-prog vmlinux.h