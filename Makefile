# mlsbond: `cargo build` builds the server and client; the Go module in go/ holds the package
# orchestrators use and the end-to-end suite.

.PHONY: all build generate test test-rust test-go clean

all: build

build:
	cargo build --release

# regenerates the Go stubs (committed) from proto/mlsbond.proto; needs protoc
generate:
	cd go && protoc -I ../proto \
		--plugin=protoc-gen-go=$$(go tool -n protoc-gen-go) \
		--plugin=protoc-gen-go-grpc=$$(go tool -n protoc-gen-go-grpc) \
		--go_out=proto --go_opt=paths=source_relative \
		--go-grpc_out=proto --go-grpc_opt=paths=source_relative \
		mlsbond.proto

test: test-rust test-go

test-rust:
	cargo test

# builds the binaries the suite runs, then runs it
test-go:
	cargo build
	cd go && go vet ./... && go test ./... -timeout 20m

# removes the build output in target/; the generated Go stubs stay, they are committed
clean:
	cargo clean
