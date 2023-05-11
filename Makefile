#created by lijk<lijk@infosec.com.cn>
ifndef CC
CC := cc
endif
CFLAGS := -g -m64 -O0 -Wall -fPIC
CFLAGS += -D__DEBUG__
CFLAGS += -I./
CFLAGS += -I./include/
LDFLAGS += -L./
LDFLAGS += -L./lib/ -lssl -lcrypto
LIBS := -ldl -pthread

.PHONY : default all clean

SRCS += ecies_ssl.c test.c

OBJS = $(SRCS:.c=.o)

TARGET = test

default : all

all : ${TARGET}

${TARGET} : ${OBJS}
	${CC} -o $@ ${OBJS} ${CFLAGS} ${LDFLAGS} ${LIBS}
	@echo "$@"

%.o : %.c %.h
	${CC} ${CFLAGS} -o $@ -c $<

clean :
	rm -rf ${OBJS} ${TARGET}
