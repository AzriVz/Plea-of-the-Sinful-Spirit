# Plea of the Sinful Spirit

Video demo: https://drive.google.com/file/d/1VzhzICr5hTYOCyZyasVYn0WKq3s41mvb/view?usp=sharing

Monitor aktivitas CPU berbasis eBPF/libbpf CO-RE untuk Linux x86-64. Program
memasang hook syscall entry/exit dan context switch, menulis event detail ke
ring buffer, serta menampilkan agregasi live per CPU.

## Prasyarat dan pemeriksaan kernel

Kernel harus menyediakan BTF pada `/sys/kernel/btf/vmlinux`. Pada
Ubuntu/Debian, periksa dan siapkan lingkungan dengan:

```bash
uname -a
sudo bpftool feature probe
ls -lh /sys/kernel/btf/vmlinux
./scripts/setup.sh
# Opsional, jika dependency belum tersedia:
./scripts/setup.sh --install
```

Build membutuhkan `clang`, `bpftool`, `libbpf`, `libelf`, `zlib`, `pkg-config`,
`gcc`, dan `make`. Target fentry bonus memakai nama simbol x86-64
`__x64_sys_openat`, sehingga port ke arsitektur lain memerlukan penyesuaian
target dan nama simbol syscall.

## Build

```bash
make all tests
sudo ./build/monitor
```

Mode default menampilkan syscall/detik dan context-switch/detik per CPU. Untuk
menampilkan setiap event sekaligus dengan live statistics:

```bash
sudo ./build/monitor --events --sample 1 --no-clear
```

Contoh bonus:

```bash
sudo ./build/monitor --page-fault-demo --sample 1 --no-clear
sudo ./build/monitor --fentry-demo --sample 1 --no-clear
sudo ./build/monitor --rate-limit /tmp/target --limit 10 --target-pid PID
```

Rate limiting hanya diaktifkan jika kernel menyediakan BPF LSM atau secara
eksplisit mencantumkan `__x64_sys_openat` sebagai target error injection.
Loader menolak menjalankan mode tersebut jika tidak ada enforcement hook yang
otoritatif; tracepoint observasional tidak dipakai untuk berpura-pura menolak
syscall.

Untuk jalur LSM, `bpf` harus benar-benar tercantum pada daftar LSM aktif, bukan
sekadar tersedia sebagai tipe program:

```bash
cat /sys/kernel/security/lsm
```

Kernel biasanya membutuhkan `CONFIG_BPF_LSM=y` dan `bpf` pada konfigurasi/order
LSM saat boot. Jika kondisi tersebut tidak terpenuhi, gunakan VM/kernel yang
mendukungnya atau target error injection yang memang di-whitelist.

Jalankan pengetesan terhadap BPF Verifier:

```bash
sudo make verifier-test
```

## Tes dan pengumpulan evidence

```bash
sudo make test-monitor
sudo make test-page-fault
sudo make test-race
sudo make test-fentry
sudo make test-rate-limit
sudo ./scripts/benchmark.sh
sudo ./scripts/collect_evidence.sh
sudo ./scripts/collect_bonus_evidence.sh
```

Evidence disimpan di `artifacts/` dan mencakup versi kernel/toolchain,
`bpftool feature probe`, program/map list, `bpftool map dump`, log verifier,
event detail, hasil race test, serta hasil benchmark.