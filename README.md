# use libbpf based on 5.11.0-37-generic
1. sudo apt install -y bison build-essential cmake flex git libedit-dev libmnl-dev zlib1g-dev libssl-dev libelf-dev libcap-dev libfl-dev llvm clang pkg-config gcc-multilib luajit libluajit-5.1-dev libncurses5-dev libclang-dev clang-tools
2. git clone https://github.com/libbpf/libbpf.git
3. cd libbpf/src && make && make install && sudo cp libbpf.a /usr/local/lib
4. sudo apt install linux-tools-$(uname -r) // (有问题可以到 https://github.com/libbpf/libbpf-bootstrap 复制一份)
5. git clone https://github.com/theanarkh/libbpf-code.git
6. cd libbpf-code/src && make
7. sudo ./hello


[使用 ebpf 监控 Node.js 事件循环的耗时](https://blog.csdn.net/THEANARKH/article/details/122006904)
