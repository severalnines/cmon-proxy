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
	echo "window.FEAS_ENV = { API_URL: '/proxy' };" > app/config.js

build: getfrontendfiles
	docker build -t severalnines/cmon-proxy . -f Dockerfile.build

run: build
	docker run -p 19051:19051 severalnines/cmon-proxy
