.PHONY: run-tam-server
run-tam-server:
	go run ./cmd/tam4wasm-mock

.PHONY: test
test:
	go test ./...

.PHONY: test-integrated
test-integrated:
	go test -tags=integration ./...

.PHONY: clean
clean:
	rm -f app.wasm manifest.app.wasm.0.suit
