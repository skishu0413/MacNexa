.PHONY: all run mock test clean logs help

all: run

run:
	@./run.sh

mock:
	@./run.sh --mock

test:
	@./run.sh --test

clean:
	@./run.sh --clean

logs:
	@./run.sh --logs

help:
	@./run.sh --help
