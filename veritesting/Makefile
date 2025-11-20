PROG = target
NO_VERI_PROG = $(PROG)_no_veri
SRC = $(PROG).c
OPT = -no-pie

all:
	gcc $(OPT) -o $(PROG) $(SRC)
	gcc -DNO_VERITESTING $(OPT) -o $(NO_VERI_PROG) $(SRC)

clean:
	rm $(PROG) $(NO_VERI_PROG)
