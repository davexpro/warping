.PHONY: build
build:
	mkdir -p output
    CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -extldflags '-static'" -o output/warping-darwin-amd64
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -extldflags '-static'" -o output/warping-linux-amd64
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -extldflags '-static'" -o output/warping-darwin-arm
