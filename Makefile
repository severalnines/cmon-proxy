.PHONY: ci getfrontendfiles build run

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

build: 
	docker build -t severalnines/cmon-proxy . -f Dockerfile.local

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


