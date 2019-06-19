CC=gcc
CFLAGS=-O2 -fno-inline -Wall -g

all: iscsid

iscsid: main.o conn.o iscsid.o log.o param.o proc.o session.o target.o md5.o

clean:
	rm -f *.o iscsid
