.PHONY: ci getfrontendfiles build builder packages run minimal-ci

DEB_PREFIX = /usr
RPM_PREFIX = /usr
BUILD_NUMBER := $(or $(BUILD_NUMBER),1)
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

# Minimal build without forcing dependency rebuilds
minimal-ci:
	CGO_ENABLED=0 \
	GOOS=linux \
	GO111MODULE=on go build \
        -gcflags=all="-N -l -m=1" \
        -o build/ccmgr \
        -ldflags "-s -w" \
        .
	CGO_ENABLED=0 \
	GOOS=linux \
	GO111MODULE=on go build \
        -gcflags=all="-N -l -m=1" \
        -o build/ccmgradm \
        -ldflags "-s -w" \
        ./ccmgradm

ci-docker:
	docker run  --platform=linux/amd64 --rm -v "$(shell pwd):/code" -w /code -it severalnines/cmon-proxy-builder make ci


packages:
	cmake . \
		-Bcmake-build \
		-DCMAKE_INSTALL_PREFIX=$(DEB_PREFIX) \
		-DBUILDNUM=$(BUILD_NUMBER) \
		-DCPACK_GENERATOR=DEB
	make -C ./cmake-build package
	cmake . \
		-Bcmake-build \
		-DCMAKE_INSTALL_PREFIX=$(RPM_PREFIX) \
		-DBUILDNUM=$(BUILD_NUMBER) \
		-DCPACK_GENERATOR=RPM
	make -C ./cmake-build package

getfrontendfiles:
	-@docker rm -f cmonproxyfe
	docker create -ti --name cmonproxyfe severalnines/cmon-proxy-fe:latest bash
	docker cp cmonproxyfe:/app ./
	docker rm -f cmonproxyfe
	echo "Pulled frontend files:"
	find ./app
	echo "window.FEAS_ENV = { API_URL: '/proxy' };" > app/config.js

build: 
	docker build -t severalnines/cmon-proxy . -f docker/Dockerfile.local

builder:
	docker buildx build --platform=linux/amd64  -t severalnines/cmon-proxy-builder . -f docker/Dockerfile.builder

builder-run:
	docker run --platform=linux/amd64 -v "$(shell pwd):/code" -p 19051:19051 -it severalnines/cmon-proxy-builder

builder-push:
	docker push severalnines/cmon-proxy-builder:latest

run:
	-@echo "Once started you can open UI at https://127.0.0.1:19051/ (accept the self-signed cert)"
	-@echo "To create/change users, find your container using docker ps, then call"
	-@echo "$$ docker exec e4a846db54b3 ./ccmgradm # replace with your container ID"
	-mkdir -p dockerdata
	docker run -v "$(shell pwd)/dockerdata:/data" -p 19051:19051 severalnines/cmon-proxy

releasetoregistry:
	bash -c 'pushd ../cmon-proxy-fe; docker build -f Dockerfile.build . -t severalnines/cmon-proxy-fe; popd'
	docker build -f Dockerfile.local . -t severalnines/clustercontrol-manager
	docker push severalnines/clustercontrol-manager:latest

# Debug targets
debug-build:
	CGO_ENABLED=0 \
	GO111MODULE=on go build \
        -gcflags="all=-N -l" \
        -o build/ccmgr-debug \
        -ldflags "-s -w" \
        .

debug-run:
	@echo "Starting cmon-proxy in debug mode..."
	@echo "Debug port: 2345"
	@echo "HTTP port: 19051"
	@echo "To connect from VS Code, use 'Attach to cmon-proxy' configuration"
	@echo ""
	GIN_MODE=debug DEBUG_WEB_RPC=true dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec ./build/ccmgr-debug -- --basedir .




