.PHONY: all run build mock test clean logs help

all: run

build:
	@./run.sh --build-only

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
