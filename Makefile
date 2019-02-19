MAJOR	?= 1
MINOR	?= 0
PATCH	?= 0

TAG	= g0dscookie/ldapauthd
TAGLIST = -t ${TAG}:${MAJOR} -t ${TAG}:${MAJOR}.${MINOR} -t ${TAG}:${MAJOR}.${MINOR}.${PATCH}
BUILDARGS = --build-arg VERSION=${MAJOR}.${MINOR}.${PATCH}

.PHONY: nothing
nothing:
	@echo "No job given."
	@exit 1

.PHONY: all
all: alpine3.9

.PHONY: all-latest
all-latest: alpine3.9-latest

.PHONY: alpine3.9
alpine3.9:
	docker build ${BUILDARGS} ${TAGLIST} .

.PHONY: alpine3.9-latest
alpine3.9-latest:
	docker build ${BUILDARGS} -t ${TAG}:latest ${TAGLIST} .

.PHONY: clean
clean:
	docker rmi -f $(shell docker images -aq ${TAG})

.PHONY: push
push:
	docker push $(TAG)