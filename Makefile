.PHONY: all build test test-race lint vuln clean run-demo eval

BIN_DIR := bin
AGENTGATE_BIN := $(BIN_DIR)/agentgate
EVAL_BIN := $(BIN_DIR)/eval-harness
MOCK_BIN := $(BIN_DIR)/mock-tools

all: test build

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(AGENTGATE_BIN) ./cmd/agentgate
	go build -o $(EVAL_BIN) ./cmd/eval-harness
	go build -o $(MOCK_BIN) ./cmd/mock-tools

test:
	go test -v ./...

test-race:
	go test -race -v ./...

test-cover:
	go test -race -coverprofile=coverage.txt -covermode=atomic ./...
	go tool cover -html=coverage.txt -o coverage.html

lint:
	golangci-lint run ./...

vuln:
	govulncheck ./...

run-demo:
	go run ./cmd/agentgate -serve :8700 -demo

eval:
	go run ./cmd/eval-harness -config configs/agentgate.yaml -cases eval/cases.json -mock-judge

clean:
	rm -rf $(BIN_DIR) coverage.txt coverage.html agentgate-audit.jsonl
