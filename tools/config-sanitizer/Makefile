SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
# .DELETE_ON_ERROR:
MAKEFLAGS = --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

# define script name
SCRIPT := autograph_config_sanitizer

# Override PWD so that it's always based on the location of the file and **NOT**
# based on where the shell is when calling `make`. This is useful if `make`
# is called like `make -C <some path>`
PWD := $(realpath $(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

WORKTREE_ROOT := $(shell git rev-parse --show-toplevel 2> /dev/null)


# Using $$() instead of $(shell) to run evaluation only when it's accessed
# https://unix.stackexchange.com/a/687206
py = $$(if [ -d $(PWD)/'.venv' ]; then echo $(PWD)/".venv/bin/python3"; else echo "python3"; fi)
pip = $(py) -m pip

.DEFAULT_GOAL := help
.PHONY: help
help: ## Display this help section
	@#awk 'BEGIN {FS = ":.*?## "} /^[\.a-zA-Z\$$/]+.*:.*?##\s/ {printf "\033[36m%-38s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@grep -E '^[\.a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.venv: requirements.txt  ## Build the virtual environment
	$(py) -m venv .venv
	$(pip) install -U pip setuptools wheel build
	$(pip) install -U -r requirements.txt
	touch .venv

build: .venv  ## Build the distribution packages
	$(py) -m build

docker-build: ## build docker image
	docker buildx build --tag $(SCRIPT) .

docker-run: ## run $(SCRIPT)
	docker run -it --rm $(SCRIPT):latest

docker-debug:  ## run bash in generated container
	docker run -it --rm $(SCRIPT):latest bash
