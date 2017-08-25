CC = gcc
#CFLAGS = -O0 -g -Wall
#LFLAGS = 
CFLAGS = -O2 -Wall
LFLAGS = -s
OBJ = dcc.o dal.o
OUT = dcc.exe

all: $(OBJ)
	$(CC) $(OBJ) $(CFLAGS) $(LFLAGS) -o $(OUT)

dcc.o: dcc.c dcc.h
	$(CC) dcc.c -c $(CFLAGS)

dal.o: dal.c pe.h
	$(CC) dal.c -c $(CFLAGS)

clean:
	rm -rf *.o $(OUT)