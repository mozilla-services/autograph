# put help first, to avoid prompting for input if only help wanted
.DEFAULT_GOAL := help
.PHONY: help
help: ## Display this help section
	@grep -E '^[\.a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

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

# Set up variables possibly needed by script, for both running in debug
# and from container
SCRIPT ?= $(shell type -p gen-apk-key.sh || echo ./gen-apk-key.sh)
PEPK ?= $(RD_PATH)/pepk.jar

# The rest of the defaults depend on the APP_NAME. We don't test for
# existance here, as they may not be needed.
PRIVATE_KEY ?= ../$(APP_NAME)-private-key.pem
PUBLIC_CERT ?= ../$(APP_NAME)-signing-cert.pem
WRAP_KEY ?= ../encryption_public_key.pem


##################################################################################
#
#     Workspace Setup
#
##################################################################################
.PHONY: status
status: _check-prerequisites _check-for-pepk  ## Report on readiness to perform tasks
	@echo "In container: $(IN_CONTAINER)"
	@echo "Using ramdisk at $(RD_PATH)"

.PHONY: _check-for-pepk
_check-for-pepk:  # Check if pepk.jar is available
	@type -ap java &>/dev/null ||  { echo "ERROR: missing java - needed for pepk" ; false ; }
	@test -r  $(PEPK) &>/dev/null || { echo "ERROR: missing $(PEPK) (try: make download-pepk)" ; false ; }

.PHONY: _check-prerequisites
_check-prerequisites:  # Verify utilities available
	@type -ap openssl &>/dev/null || { echo "ERROR: Missing openssl" ; false ; }
	@type $(SCRIPT) &>/dev/null || { echo "ERROR: not available $(SCRIPT)" ; false ; }
	@test -w $(RD_PATH)/t || { echo "ERROR: $(RD_PATH)/t is not writable (try: make setup-ramdisk)" ; false ; }
	@{ ! $(IN_CONTAINER) && type -ap docker &>/dev/null ; } || { echo "ERROR: docker not available" ; false ; }
	@$(IN_CONTAINER) || echo "Warning: not running in a container"

.PHONY: download-pepk
download-pepk: $(PEPK)	## Download pepk.jar
$(PEPK):
	@curl --silent --fail \
		--output $@ \
		https://www.gstatic.com/play-apps-publisher-rapid/signing-tool/prod/pepk.jar
	@echo Downloaded to $(PEPK)

.PHONY: setup-ramdisk
setup-ramdisk: $(RD_PATH)/t	## Create a container writeable directory
$(RD_PATH)/t:
	@mkdir $@
	@chmod a+w $@
	@echo "Container writeable directory configured"

.PHONY: docker-run
docker-run:  ## Start docker container (from host)
	@! $(IN_CONTAINER) || { echo "ERROR: already in container" ; false ; }
	docker run -it --rm \
		-v $(RAM_DISK):/secrets \
		$(CONTAINER_IMAGE):$(CONTAINER_VERSION) \
		bash -c /app/src/autograph/tools/android-store/start-container-shell.sh

.PHONY: _check_app_name
_check_app_name:  # check that we have a definition from somewhere
	@test -n "$(APP_NAME)" || { echo "Please supply APP_NAME on command line or via env var" ; false ; }

.PHONY: _check_key_inputs
_check_key_inputs:  _check_app_name # Check that the inputs are where we expect them
	@test -r "$(PRIVATE_KEY)" || { echo "Can't read private key '$(PRIVATE_KEY)'" ; false ; }
	@test -r "$(PUBLIC_CERT)" || { echo "Can't read certificate '$(PUBLIC_CERT)'" ; false ; }
	@test -r "$(WRAP_KEY)"    || { echo "Can't read wrap key '$(WRAP_KEY)'" ; false ; }

##################################################################################
#
#     Key Manipulation
#
##################################################################################
.PHONY: apk-new-app-create-key
apk-new-app-create-key: _check-prerequisites _check_app_name  ## Create signing key for NEW Android app (step 1 of 2)
	$(SCRIPT) --no-pepk "$(APP_NAME)"

.PHONY: apk-new-app-wrap-key apk-existing-app-wrap-key _wrap_key
_wrap_key: _check-prerequisites _check_key_inputs _check-for-pepk # Wrap signing key
	$(SCRIPT) \
		--key "$(PRIVATE_KEY)" \
		--certificate "$(PUBLIC_CERT)" \
		--wrap-key "$(WRAP_KEY)" \
		--pepk "$(PEPK)" \
		"$(APP_NAME)"
apk-existing-app-wrap-key: _wrap_key ## Wrap signing key for existing Android app
apk-new-app-wrap-key: _wrap_key ## Wrap signing key for NEW Android app (step 2 of 2)
