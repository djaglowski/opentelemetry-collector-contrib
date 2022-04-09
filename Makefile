include ./Makefile.Common

RUN_CONFIG?=local/config.yaml
CMD?=
OTEL_VERSION=main

BUILD_INFO_IMPORT_PATH=github.com/open-telemetry/opentelemetry-collector-contrib/internal/version
VERSION=$(shell git describe --always --match "v[0-9]*" HEAD)
BUILD_INFO=-ldflags "-X $(BUILD_INFO_IMPORT_PATH).Version=$(VERSION)"

COMP_REL_PATH=internal/components/components.go
MOD_NAME=github.com/open-telemetry/opentelemetry-collector-contrib

FIND_MOD_ARGS=-type f -name "go.mod"
TO_MOD_DIR=-exec dirname {} \; | sort | egrep  '^./'
EX_COMPONENTS=-not -path "./receiver/*" -not -path "./processor/*" -not -path "./exporter/*" -not -path "./extension/*"
EX_INTERNAL=-not -path "./internal/*"

# ALL_MODULES includes ./* dirs (excludes . dir and example with go code)
ALL_MODULES := $(shell find . $(FIND_MOD_ARGS) $(TO_MOD_DIR) )
RECEIVER_MODULES := $(shell find ./receiver/* $(FIND_MOD_ARGS) $(TO_MOD_DIR) )
PROCESSOR_MODULES := $(shell find ./processor/* $(FIND_MOD_ARGS) $(TO_MOD_DIR) )
EXPORTER_MODULES := $(shell find ./exporter/* $(FIND_MOD_ARGS) $(TO_MOD_DIR) )
EXTENSION_MODULES := $(shell find ./extension/* $(FIND_MOD_ARGS) $(TO_MOD_DIR) )
INTERNAL_MODULES := $(shell find ./internal/* $(FIND_MOD_ARGS) $(TO_MOD_DIR) )
OTHER_MODULES := $(shell find . $(EX_COMPONENTS) $(EX_INTERNAL) $(FIND_MOD_ARGS) $(TO_MOD_DIR) )

# Modules to run integration tests on.
# XXX: Find a way to automatically populate this. Too slow to run across all modules when there are just a few.
INTEGRATION_TEST_MODULES := \
	internal/containertest \
	receiver/apachereceiver \
	receiver/dockerstatsreceiver \
	receiver/jmxreceiver/ \
	receiver/kafkametricsreceiver \
	receiver/memcachedreceiver \
	receiver/mysqlreceiver \
	receiver/nginxreceiver \
	receiver/postgresqlreceiver \
	receiver/redisreceiver \
	receiver/riakreceiver \
	receiver/zookeeperreceiver \
	extension/observer/dockerobserver

.DEFAULT_GOAL := all

all-modules:
	@echo $(ALL_MODULES) | tr ' ' '\n' | sort

.PHONY: all
all: common gotest otelcontribcol otelcontribcol-unstable

.PHONY: e2e-test
e2e-test: otelcontribcol otelcontribcol-unstable
	$(MAKE) -C testbed run-tests

.PHONY: unit-tests-with-cover
unit-tests-with-cover:
	@echo Verifying that all packages have test files to count in coverage
	@internal/buildscripts/check-test-files.sh $(subst github.com/open-telemetry/opentelemetry-collector-contrib/,./,$(ALL_PKGS))
	@$(MAKE) for-all-target TARGET="do-unit-tests-with-cover"

.PHONY: integration-tests-with-cover
integration-tests-with-cover:
	@echo $(INTEGRATION_TEST_MODULES)
	@$(MAKE) for-all-target TARGET="do-integration-tests-with-cover" ALL_MODULES="$(INTEGRATION_TEST_MODULES)"

# Long-running e2e tests
.PHONY: stability-tests
stability-tests: otelcontribcol
	@echo Stability tests are disabled until we have a stable performance environment.
	@echo To enable the tests replace this echo by $(MAKE) -C testbed run-stability-tests

.PHONY: gotidy
gotidy:
	$(MAKE) for-all-target TARGET="tidy"

.PHONY: gomoddownload
gomoddownload:
	$(MAKE) for-all-target TARGET="moddownload"

.PHONY: gotest
gotest:
	$(MAKE) for-all-target TARGET="test"

.PHONY: gofmt
gofmt:
	$(MAKE) for-all-target TARGET="fmt"

.PHONY: golint
golint:
	$(MAKE) for-all-target TARGET="lint"

.PHONY: golint-receivers
golint-receivers:
	$(MAKE) for-all-receivers TARGET="lint"

.PHONY: golint-processors
golint-processors:
	$(MAKE) for-all-processors TARGET="lint"

.PHONY: golint-exporters
golint-exporters:
	$(MAKE) for-all-exporters TARGET="lint"

.PHONY: golint-extensions
golint-extensions:
	$(MAKE) for-all-extensions TARGET="lint"

.PHONY: golint-internal
golint-internal:
	$(MAKE) for-all-internal TARGET="lint"

.PHONY: golint-others
golint-others:
	$(MAKE) for-all-others TARGET="lint"

.PHONY: goporto
goporto:
	porto -w --include-internal --skip-dirs "^cmd$$" ./

.PHONY: for-all
for-all:
	@echo "running $${CMD} in root"
	@$${CMD}
	@set -e; for dir in $(ALL_MODULES); do \
	  (cd "$${dir}" && \
	  	echo "running $${CMD} in $${dir}" && \
	 	$${CMD} ); \
	done

.PHONY: add-tag
add-tag:
	@[ "${TAG}" ] || ( echo ">> env var TAG is not set"; exit 1 )
	@echo "Adding tag ${TAG}"
	@git tag -a ${TAG} -s -m "Version ${TAG}"
	@set -e; for dir in $(ALL_MODULES); do \
	  (echo Adding tag "$${dir:2}/$${TAG}" && \
	 	git tag -a "$${dir:2}/$${TAG}" -s -m "Version ${dir:2}/${TAG}" ); \
	done

.PHONY: push-tag
push-tag:
	@[ "${TAG}" ] || ( echo ">> env var TAG is not set"; exit 1 )
	@echo "Pushing tag ${TAG}"
	@git push upstream ${TAG}
	@set -e; for dir in $(ALL_MODULES); do \
	  (echo Pushing tag "$${dir:2}/$${TAG}" && \
	 	git push upstream "$${dir:2}/$${TAG}"); \
	done

.PHONY: delete-tag
delete-tag:
	@[ "${TAG}" ] || ( echo ">> env var TAG is not set"; exit 1 )
	@echo "Deleting tag ${TAG}"
	@git tag -d ${TAG}
	@set -e; for dir in $(ALL_MODULES); do \
	  (echo Deleting tag "$${dir:2}/$${TAG}" && \
	 	git tag -d "$${dir:2}/$${TAG}" ); \
	done

DEPENDABOT_PATH=".github/dependabot.yml"
.PHONY: gendependabot
gendependabot:
	@echo "Recreating ${DEPENDABOT_PATH} file"
	@echo "# File generated by \"make gendependabot\"; DO NOT EDIT." > ${DEPENDABOT_PATH}
	@echo "" >> ${DEPENDABOT_PATH}
	@echo "version: 2" >> ${DEPENDABOT_PATH}
	@echo "updates:" >> ${DEPENDABOT_PATH}
	@echo "Add entry for \"/\" github-actions"
	@echo "  - package-ecosystem: \"github-actions\"" >> ${DEPENDABOT_PATH}
	@echo "    directory: \"/\"" >> ${DEPENDABOT_PATH}
	@echo "    schedule:" >> ${DEPENDABOT_PATH}
	@echo "      interval: \"weekly\"" >> ${DEPENDABOT_PATH}
	@echo "Add entry for \"/\" docker"
	@echo "  - package-ecosystem: \"docker\"" >> ${DEPENDABOT_PATH}
	@echo "    directory: \"/\"" >> ${DEPENDABOT_PATH}
	@echo "    schedule:" >> ${DEPENDABOT_PATH}
	@echo "      interval: \"weekly\"" >> ${DEPENDABOT_PATH}
	@echo "Add entry for \"/\" gomod"
	@echo "  - package-ecosystem: \"gomod\"" >> ${DEPENDABOT_PATH}
	@echo "    directory: \"/\"" >> ${DEPENDABOT_PATH}
	@echo "    schedule:" >> ${DEPENDABOT_PATH}
	@echo "      interval: \"weekly\"" >> ${DEPENDABOT_PATH}
	@set -e; for dir in $(ALL_MODULES); do \
		echo "Add entry for \"$${dir:1}\""; \
		echo "  - package-ecosystem: \"gomod\"" >> ${DEPENDABOT_PATH}; \
		echo "    directory: \"$${dir:1}\"" >> ${DEPENDABOT_PATH}; \
		echo "    schedule:" >> ${DEPENDABOT_PATH}; \
		echo "      interval: \"weekly\"" >> ${DEPENDABOT_PATH}; \
	done

GOMODULES = $(ALL_MODULES) $(PWD)
.PHONY: $(GOMODULES)
MODULEDIRS = $(GOMODULES:%=for-all-target-%)
for-all-target: $(MODULEDIRS)
$(MODULEDIRS):
	$(MAKE) -C $(@:for-all-target-%=%) $(TARGET)
.PHONY: for-all-target

GOMODULES = $(RECEIVER_MODULES) $(PWD)
.PHONY: $(GOMODULES)
MODULEDIRS = $(GOMODULES:%=for-all-receivers-%)
for-all-receivers: $(MODULEDIRS)
$(MODULEDIRS):
	$(MAKE) -C $(@:for-all-receivers-%=%) $(TARGET)
.PHONY: for-all-receivers

GOMODULES = $(PROCESSOR_MODULES) $(PWD)
.PHONY: $(GOMODULES)
MODULEDIRS = $(GOMODULES:%=for-all-processors-%)
for-all-processors: $(MODULEDIRS)
$(MODULEDIRS):
	$(MAKE) -C $(@:for-all-processors-%=%) $(TARGET)
.PHONY: for-all-processors

GOMODULES = $(EXPORTER_MODULES) $(PWD)
.PHONY: $(GOMODULES)
MODULEDIRS = $(GOMODULES:%=for-all-exporters-%)
for-all-exporters: $(MODULEDIRS)
$(MODULEDIRS):
	$(MAKE) -C $(@:for-all-exporters-%=%) $(TARGET)
.PHONY: for-all-exporters

GOMODULES = $(EXTENSION_MODULES) $(PWD)
.PHONY: $(GOMODULES)
MODULEDIRS = $(GOMODULES:%=for-all-extensions-%)
for-all-extensions: $(MODULEDIRS)
$(MODULEDIRS):
	$(MAKE) -C $(@:for-all-extensions-%=%) $(TARGET)
.PHONY: for-all-extensions

GOMODULES = $(INTERNAL_MODULES) $(PWD)
.PHONY: $(GOMODULES)
MODULEDIRS = $(GOMODULES:%=for-all-internal-%)
for-all-internal: $(MODULEDIRS)
$(MODULEDIRS):
	$(MAKE) -C $(@:for-all-internal-%=%) $(TARGET)
.PHONY: for-all-internal

GOMODULES = $(OTHER_MODULES) $(PWD)
.PHONY: $(GOMODULES)
MODULEDIRS = $(GOMODULES:%=for-all-others-%)
for-all-others: $(MODULEDIRS)
$(MODULEDIRS):
	$(MAKE) -C $(@:for-all-others-%=%) $(TARGET)
.PHONY: for-all-others

TOOLS_MOD_DIR := ./internal/tools
.PHONY: install-tools
install-tools:
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install github.com/client9/misspell/cmd/misspell
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install github.com/golangci/golangci-lint/cmd/golangci-lint
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install github.com/google/addlicense
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install github.com/jstemmer/go-junit-report
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install github.com/pavius/impi/cmd/impi
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install github.com/tcnksm/ghr
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install go.opentelemetry.io/build-tools/checkdoc
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install go.opentelemetry.io/build-tools/issuegenerator
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install golang.org/x/tools/cmd/goimports
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install go.opentelemetry.io/build-tools/multimod
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install github.com/jcchavezs/porto/cmd/porto
	cd $(TOOLS_MOD_DIR) && $(GOCMD) install go.opentelemetry.io/build-tools/crosslink

.PHONY: run
run:
	GO111MODULE=on $(GOCMD) run --race ./cmd/otelcontribcol/... --config ${RUN_CONFIG} ${RUN_ARGS}

.PHONY: docker-component # Not intended to be used directly
docker-component: check-component
	GOOS=linux GOARCH=amd64 $(MAKE) $(COMPONENT)
	cp ./bin/$(COMPONENT)_linux_amd64 ./cmd/$(COMPONENT)/$(COMPONENT)
	docker build -t $(COMPONENT) ./cmd/$(COMPONENT)/
	rm ./cmd/$(COMPONENT)/$(COMPONENT)

.PHONY: check-component
check-component:
ifndef COMPONENT
	$(error COMPONENT variable was not defined)
endif

.PHONY: docker-otelcontribcol
docker-otelcontribcol:
	COMPONENT=otelcontribcol $(MAKE) docker-component

.PHONY: generate
generate:
	cd cmd/mdatagen && $(GOCMD) install .
	$(MAKE) for-all CMD="$(GOCMD) generate ./..."

# Build the Collector executable.
.PHONY: otelcontribcol
otelcontribcol:
	GO111MODULE=on CGO_ENABLED=0 $(GOCMD) build -trimpath -o ./bin/otelcontribcol_$(GOOS)_$(GOARCH)$(EXTENSION) \
		$(BUILD_INFO) -tags $(GO_BUILD_TAGS) ./cmd/otelcontribcol

# Build the Collector executable, including unstable functionality.
.PHONY: otelcontribcol-unstable
otelcontribcol-unstable:
	GO111MODULE=on CGO_ENABLED=0 $(GOCMD) build -trimpath -o ./bin/otelcontribcol_unstable_$(GOOS)_$(GOARCH)$(EXTENSION) \
		$(BUILD_INFO) -tags $(GO_BUILD_TAGS),enable_unstable ./cmd/otelcontribcol

.PHONY: otelcontribcol-all-sys
otelcontribcol-all-sys: otelcontribcol-darwin_amd64 otelcontribcol-darwin_arm64 otelcontribcol-linux_amd64 otelcontribcol-linux_arm64 otelcontribcol-windows_amd64

.PHONY: otelcontribcol-darwin_amd64
otelcontribcol-darwin_amd64:
	GOOS=darwin  GOARCH=amd64 $(MAKE) otelcontribcol

.PHONY: otelcontribcol-darwin_arm64
otelcontribcol-darwin_arm64:
	GOOS=darwin  GOARCH=arm64 $(MAKE) otelcontribcol

.PHONY: otelcontribcol-linux_amd64
otelcontribcol-linux_amd64:
	GOOS=linux   GOARCH=amd64 $(MAKE) otelcontribcol

.PHONY: otelcontribcol-linux_arm64
otelcontribcol-linux_arm64:
	GOOS=linux   GOARCH=arm64 $(MAKE) otelcontribcol

.PHONY: otelcontribcol-windows_amd64
otelcontribcol-windows_amd64:
	GOOS=windows GOARCH=amd64 EXTENSION=.exe $(MAKE) otelcontribcol

.PHONY: update-dep
update-dep:
	$(MAKE) for-all-target TARGET="updatedep"
	$(MAKE) otelcontribcol

.PHONY: update-otel
update-otel:
	$(MAKE) update-dep MODULE=go.opentelemetry.io/collector VERSION=$(OTEL_VERSION)

.PHONY: otel-from-tree
otel-from-tree:
	# This command allows you to make changes to your local checkout of otel core and build
	# contrib against those changes without having to push to github and update a bunch of
	# references. The workflow is:
	#
	# 1. Hack on changes in core (assumed to be checked out in ../opentelemetry-collector from this directory)
	# 2. Run `make otel-from-tree` (only need to run it once to remap go modules)
	# 3. You can now build contrib and it will use your local otel core changes.
	# 4. Before committing/pushing your contrib changes, undo by running `make otel-from-lib`.
	$(MAKE) for-all CMD="$(GOCMD) mod edit -replace go.opentelemetry.io/collector=$(SRC_ROOT)/../opentelemetry-collector"

.PHONY: otel-from-lib
otel-from-lib:
	# Sets opentelemetry core to be not be pulled from local source tree. (Undoes otel-from-tree.)
	$(MAKE) for-all CMD="$(GOCMD) mod edit -dropreplace go.opentelemetry.io/collector"

.PHONY: build-examples
build-examples:
	docker-compose -f examples/tracing/docker-compose.yml build
	docker-compose -f exporter/splunkhecexporter/example/docker-compose.yml build

.PHONY: deb-rpm-package
%-package: ARCH ?= amd64
%-package:
	$(MAKE) otelcontribcol-linux_$(ARCH)
	docker build -t otelcontribcol-fpm internal/buildscripts/packaging/fpm
	docker run --rm -v $(CURDIR):/repo -e PACKAGE=$* -e VERSION=$(VERSION) -e ARCH=$(ARCH) otelcontribcol-fpm

# Verify existence of READMEs for components specified as default components in the collector.
.PHONY: checkdoc
checkdoc:
	checkdoc --project-path $(CURDIR) --component-rel-path $(COMP_REL_PATH) --module-name $(MOD_NAME)

# Function to execute a command. Note the empty line before endef to make sure each command
# gets executed separately instead of concatenated with previous one.
# Accepts command to execute as first parameter.
define exec-command
$(1)

endef

# List of directories where certificates are stored for unit tests.
CERT_DIRS := receiver/sapmreceiver/testdata \
             receiver/signalfxreceiver/testdata \
             receiver/splunkhecreceiver/testdata

# Generate certificates for unit tests relying on certificates.
.PHONY: certs
certs:
	$(foreach dir, $(CERT_DIRS), $(call exec-command, @internal/buildscripts/gen-certs.sh -o $(dir)))

.PHONY: multimod-verify
multimod-verify: install-tools
	@echo "Validating versions.yaml"
	multimod verify

.PHONY: multimod-prerelease
multimod-prerelease: install-tools
	multimod prerelease -v ./versions.yaml -m contrib-base

.PHONY: crosslink
crosslink: install-tools
	@echo "Executing crosslink"
	crosslink --root=$(shell pwd)
