parse: parse.c
	gcc -Wall -O3 -o parse parse.c

venv:
	rm -rf venv
	python3 -m virtualenv venv
	venv/bin/pip3 install setuptools pycoin

clean:
	rm -f parse

.PHONY: clean venv
