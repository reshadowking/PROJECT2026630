CC      = gcc
CFLAGS  = -Wall -Wextra -O3 -march=native -g -pthread -DLOG_ACTIVE_LEVEL=LOG_LEVEL_INFO
INCLUDE = -I./include
LDFLAGS = -lpcap -lpthread -lncursesw
TARGET  = sniffer
SRCDIR  = src
OBJDIR  = obj

SRCS = $(SRCDIR)/main.c \
       $(SRCDIR)/capture.c \
       $(SRCDIR)/parser.c \
       $(SRCDIR)/traffic_stat.c \
       $(SRCDIR)/tcp_reassemble.c \
       $(SRCDIR)/http_parser.c \
       $(SRCDIR)/tls_sni.c \
       $(SRCDIR)/dns.c \
       $(SRCDIR)/ui.c \
       $(SRCDIR)/logger.c

OBJS = $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
DEPS = $(OBJS:.o=.d)

.PHONY: all clean debug

all: $(TARGET)

debug: CFLAGS = -Wall -Wextra -O3 -march=native -g -pthread -DLOG_ACTIVE_LEVEL=LOG_LEVEL_DEBUG
debug: clean $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build OK: $(TARGET)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDE) -MMD -MP -c -o $@ $<

clean:
	rm -rf $(OBJDIR) $(SRCDIR)/*.o $(TARGET)

-include $(DEPS)
