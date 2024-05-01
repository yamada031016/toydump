OBJS = toydump.o analyze.o print.o checksum.o
SRCS = $(OBJS:%.o=%.c)
# CFLAGS = -g -Wall
CFLAGS = -Os
LDLIBS = 
TARGET = toydump

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

clean:
	rm -f *.o *.pcap toydump
