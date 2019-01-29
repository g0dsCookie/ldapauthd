MAJOR       ?= 0
MINOR       ?= 1
MAINTENANCE ?= 0
BUILD       ?= $(shell date +'%Y.%m.%d-%H.%M.%S')
BUILD_DATE  ?= $(shell date +'%Y.%m.%d-%H:%M:%S')

.PHONY: all
all: build push

.PHONY: build
build:
	docker build \
		--build-arg VERSION=${MAJOR}.${MINOR}.${MAINTENANCE} \
		--build-arg BUILD=${MAJOR}.${MINOR}.${MAINTENANCE}-${BUILD} \
		--build-arg BUILD_DATE=${BUILD_DATE} \
		-t g0dscookie/ldapauthd:latest \
		-t g0dscookie/ldapauthd:${MAJOR} \
		-t g0dscookie/ldapauthd:${MAJOR}.${MINOR} \
		-t g0dscookie/ldapauthd:${MAJOR}.${MINOR}.${MAINTENANCE} \
		-t g0dscookie/ldapauthd:${MAJOR}.${MINOR}.${MAINTENANCE}.${BUILD} \
		.

.PHONY: push
push:
	docker push g0dscookie/ldapauthd

.PHONY: clean
clean:
	docker rmi -f $(shell docker images -aq g0dscookie/ldapauthd)
