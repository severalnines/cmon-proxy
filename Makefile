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
	CGO_ENABLED=0 \
	GOOS=linux \
	GO111MODULE=on go build \
        -a \
        -o build/ccmgradm \
        -ldflags "-s -w -extldflags -static" \
        ./ccmgradm

getfrontendfiles:
	-@docker rm -f cmonproxyfe
	docker create -ti --name cmonproxyfe severalnines/cmon-proxy-fe:latest bash
	docker cp cmonproxyfe:/app ./
	docker rm -f cmonproxyfe
	echo "Pulled frontend files:"
	find ./app
