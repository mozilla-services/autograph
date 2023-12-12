SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
# .DELETE_ON_ERROR:
MAKEFLAGS = --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

RAM_DISK ?= /tmp/ramdisk
IN_CONTAINER := $(shell test "$$(cat /proc/self/cgroup | cut -d: -f3 | sort -u )" == "/" && echo false || echo true)
RD_PATH := $(shell $(IN_CONTAINER) && echo /secrets || echo $(RAM_DISK))

CONTAINER_VERSION ?= latest
# for testing, use 'autograph-app' for the locally build image from
# 'make build' at the workspace root
CONTAINER_IMAGE ?= mozilla/autograph

.DEFAULT_GOAL := help
.PHONY: help
help: ## Display this help section
	@grep -E '^[\.a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: status
status: check-prerequisites  ## Report on readiness to perform tasks
	@echo "In container: $(IN_CONTAINER)"
	@echo "Using ramdisk at $(RD_PATH)"

.PHONY: check-prerequisites
check-prerequisites:  ## Verify utilities available
	@type -ap openssl &>/dev/null || { echo "ERROR: Missing openssl" ; false ; }
	@type -ap java &>/dev/null ||  echo "Warning: missing java - needed for pepk" 
	@type -ap ../pepk.jar &>/dev/null || echo "Warning: missing ../pepk.jar - needed for pepk" 
	@test -w $(RD_PATH)/t || { echo "ERROR: $(RD_PATH)/t is not writable" ; false ; }
	@{ ! $(IN_CONTAINER) && type -ap docker &>/dev/null ; } || { echo "ERROR: docker not available" ; false ; }
	@$(IN_CONTAINER) || echo "Warning: not running in a container"

.PHONY: docker-run
docker-run:  ## Start docker container
	@! $(IN_CONTAINER) || { echo "ERROR: already in container" ; false ; }
	docker run -it --rm \
		-v $(RAM_DISK):/secrets \
		$(CONTAINER_IMAGE):$(CONTAINER_VERSION) \
		bash -c /app/src/autograph/tools/android-store/start-container-shell.sh
