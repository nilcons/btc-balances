parse: parse.c
	gcc -Wall -O3 -o parse parse.c

clean:
	rm -f parse

.PHONY: clean
