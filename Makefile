MAJOR	?= 1
MINOR	?= 3
PATCH	?= 0

TAG	= g0dscookie/ldapauthd
TAGLIST = -t ${TAG}:${MAJOR} -t ${TAG}:${MAJOR}.${MINOR} -t ${TAG}:${MAJOR}.${MINOR}.${PATCH}
BUILDARGS = --build-arg VERSION=${MAJOR}.${MINOR}.${PATCH}

build:
	docker build ${BUILDARGS} ${TAGLIST} .

latest: TAGLIST := -t ${TAG}:latest ${TAGLIST}
latest: build

clean:
	docker rmi -f $(shell docker images -qt ${TAG})

push:
	docker push ${TAG}

.PHONY: build latest clean push