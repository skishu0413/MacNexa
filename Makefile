.PHONY: all run build mock test clean logs help

all: run

build:
	@./run.sh --build-only

run:
	@./run.sh

mock:
	@./run.sh --mock

test:
	@swift test --package-path MacNexaCore 2>/dev/null || ./run.sh --build-only

clean:
	@./run.sh --clean

logs:
	@./run.sh --logs

help:
	@./run.sh --help
