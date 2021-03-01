.PHONY: ci

# make a ci build
ci:
	CGO_ENABLED=0 \
	GOOS=linux \
	GO111MODULE=on go build \
        -a \
        -o build/ccmgr \
        -ldflags "-s -w -extldflags -static" \
        .
