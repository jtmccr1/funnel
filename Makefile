GOPATH := $(shell pwd)/build:$(shell pwd)
export SHELL=/bin/bash
export GOPATH
PATH := ${PATH}:$(shell pwd)/bin:$(shell pwd)/build/bin
export PATH
PYTHONPATH := ${PYTHONPATH}:$(shell pwd)/python
export PYTHONPATH

PROTO_INC=-I ./ -I $(GOPATH)/src/vendor/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis
GRPC_HTTP_MOD=Mgoogle/api/annotations.proto=github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis/google/api

install: depends
	go install funnel

proto: depends
	@go get ./src/vendor/github.com/golang/protobuf/protoc-gen-go/
	@go get ./src/vendor/github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway/
	@cd src/funnel/proto/tes && protoc \
		$(PROTO_INC) \
		--go_out=$(GRPC_HTTP_MOD),plugins=grpc:. \
		--grpc-gateway_out=logtostderr=true:. \
		tes.proto
	@cd src/funnel/proto/funnel && protoc \
		$(PROTO_INC) \
		-I ../tes \
		--go_out=$(GRPC_HTTP_MOD),Mtes.proto=funnel/proto/tes,plugins=grpc:. \
		--grpc-gateway_out=logtostderr=true:. \
		funnel.proto

depends:
	git submodule update --init --recursive
	go get -d funnel

serve-doc:
	godoc --http=:6060

add_deps: 
	go get github.com/dpw/vendetta
	./build/bin/vendetta src/

prune_deps:
	go get github.com/dpw/vendetta
	./build/bin/vendetta -p src/

tidy:
	pip install -q autopep8
	@find ./src/funnel* -type f | grep -v ".pb." | grep -E '.*\.go$$' | xargs gofmt -w -s
	@find ./* -type f | grep -E '.*\.py$$' | grep -v "/venv/" | grep -v "/web/node" | xargs autopep8 --in-place --aggressive --aggressive

lint:
	pip install -q flake8
	flake8 --exclude ./venv,./web .
	go get github.com/alecthomas/gometalinter
	./build/bin/gometalinter --install > /dev/null
	./build/bin/gometalinter --disable-all --enable=vet --enable=golint --enable=gofmt --vendor -s ga4gh -s proto -s web ./src/funnel/...

go-test:
	go test funnel/...

test:	go-test
	docker build -t tes-wait -f tests/docker_files/tes-wait/Dockerfile tests/docker_files/tes-wait/
	pip2.7 install -q -r tests/requirements.txt
	nosetests-2.7 tests/

web:
	mkdir -p build/web
	npm install --prefix ./web
	./web/node_modules/.bin/browserify web/app.js -o build/web/bundle.js
	./web/node_modules/.bin/node-sass web/style.scss build/web/style.css
	cp web/*.html build/web/
	go get -u github.com/jteeuwen/go-bindata/...
	go-bindata -pkg web -prefix "build/" -o src/funnel/web/web.go build/web

cross-compile: depends
	for GOOS in darwin linux; do \
		for GOARCH in 386 amd64; do \
			GOOS=$$GOOS GOARCH=$$GOARCH go build -o ./bin/funnel-$$GOOS-$$GOARCH funnel; \
		done; \
	done

upload-latest:
	go get github.com/aktau/github-release
	@if [ -z "$$GITHUB_TOKEN" ]; then \
	  echo 'GITHUB_TOKEN env. var. is required but not set'; \
		exit 1; \
	fi
	@if [ $$(git rev-parse --abbrev-ref HEAD) != 'master' ]; then \
		echo 'This command should only be run from the master branch'; \
		exit 1; \
	fi
	make cross-compile
	for GOOS in darwin linux; do \
		for GOARCH in 386 amd64; do \
			github-release upload \
			-u ohsu-comp-bio \
			-r funnel \
			--name funnel-$$GOOS-$$GOARCH \
			--tag latest \
			--replace \
			--file ./bin/funnel-$$GOOS-$$GOARCH; \
		done; \
	done

cross-compile:
	GOOS=linux GOARCH=amd64 make

full: proto install prune_deps add_deps tidy lint test web

.PHONY: proto web

