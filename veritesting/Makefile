PROG = target
SRC = $(PROG).c
OPT = -no-pie

all:
	gcc $(OPT) -o $(PROG) $(SRC)
	gcc -DNO_VERITESTING $(OPT) -o $(PROG)_no_veri $(SRC)
