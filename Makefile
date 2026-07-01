CC = gcc
CFLAGS = -Wall -g -I./include
LIBS = -lpcap -lpthread

# 新增 src/dns.o 编译目标
OBJ = src/main.o src/capture.o src/parser.o src/traffic_stat.o src/tcp_reassemble.o src/tls_sni.o src/dns.o

# 链接生成可执行程序
sniffer: $(OBJ)
	$(CC) $(OBJ) -o sniffer $(LIBS)

# 通用编译规则：src下c文件编译为对应o，依赖全部头文件
src/%.o: src/%.c include/*.h
	$(CC) $(CFLAGS) -c $< -o $@

# 清理编译产物
clean:
	rm -rf $(OBJ) sniffer