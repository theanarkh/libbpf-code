# libbpf-code
1. sudo apt install -y bison build-essential cmake flex git libedit-dev pkg-config libmnl-dev \
   python zlib1g-dev libssl-dev libelf-dev libcap-dev libfl-dev llvm clang pkg-config \
   gcc-multilib luajit libluajit-5.1-dev libncurses5-dev libclang-dev clang-tools
2. git clone https://github.com/libbpf/libbpf.git
3. cd libbpf/src && make && make install && sudo cp libbpf.a /usr/local/lib
4. sudo apt install linux-tools-$(uname -r)
5. git clone https://github.com/theanarkh/libbpf-code.git
6. cd libbpf-code/src && make
7. sudo ./hello

