.PHONY: build run clean tidy

build:
	go build -o demo/server

run_server:
	./demo/server --config demo/statements.yaml

run_collector:
	../../bin/otelcontribcol_darwin_arm64 --config ./demo/config.yaml

clean:
	rm -f demo/server

tidy:
	go mod tidy

.DEFAULT_GOAL := build