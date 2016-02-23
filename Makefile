all:
	gcc -Wall -o shelleval shelleval.c

clean:
	rm -f shelleval

.PHONY: clean
