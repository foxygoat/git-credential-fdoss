# Run `make help` to display help
.DEFAULT_GOAL := help

# --- Global -------------------------------------------------------------------
O = out
COVERAGE = 0
VERSION ?= $(shell git describe --tags --dirty --always)

## Build and lint
all: build lint
	@if [ -e .git/rebase-merge ]; then git --no-pager log -1 --pretty='%h %s'; fi
	@echo '$(COLOUR_GREEN)Success$(COLOUR_NORMAL)'

## Full clean build and up-to-date checks as run on CI
ci: clean check-uptodate all

check-uptodate: tidy
	test -z "$$(git status --porcelain -- go.mod go.sum)" || { git status; false; }

## Remove generated files
clean::
	-rm -rf $(O)

.PHONY: all check-uptodate ci clean

# --- Build --------------------------------------------------------------------
# git credential helpers need to be called git-credential-<name> for git to
# find it when the config is set up to use the <name> credential helper.
BIN_NAME = git-credential-fdoss
# We want a statically linked binary. github.com/godbus/dbus/v5 imports "net"
# and "os/user", so specify the build tags to use the Go versions of these and
# not the libc ones so that we get a static binary.
GO_TAGS = netgo,osusergo
GO_LDFLAGS = -X main.version=$(VERSION)
GO_FLAGS += $(if $(GO_TAGS),-tags='$(GO_TAGS)')
GO_FLAGS += $(if $(GO_LDFLAGS),-ldflags='$(GO_LDFLAGS)')
GO_BIN_SUFFIX = $(if $(GOOS),_$(GOOS))$(if $(GOARCH),_$(GOARCH))
GO_BIN_NAME = $(BIN_NAME)$(GO_BIN_SUFFIX)

## Build git-credential-fdoss binary
build: | $(O)
	go build -o $(O)/$(GO_BIN_NAME) $(GO_FLAGS) .

## Tidy go modules with "go mod tidy"
tidy:
	go mod tidy

.PHONY: build tidy

# --- Lint ---------------------------------------------------------------------
## Lint go source code
lint:
	golangci-lint run

.PHONY: lint

# --- Docs ---------------------------------------------------------------------

godoc: build
	./bin/gengodoc.awk main.go > $(O)/out.go
	mv $(O)/out.go main.go

.PHONY: godoc

# --- Release ------------------------------------------------------------------
RELEASE_DIR = $(O)/release

## Tag and release binaries for different OS on GitHub release
release: tag-release .WAIT build-release .WAIT publish-release

tag-release: nexttag
	git tag $(RELEASE_TAG)
	git push origin $(RELEASE_TAG)

build-release:
	$(MAKE) build GOOS=linux GOARCH=amd64 O=$(RELEASE_DIR)
	$(MAKE) build GOOS=linux GOARCH=arm64 O=$(RELEASE_DIR)
	$(MAKE) build GOOS=linux GOARCH=arm O=$(RELEASE_DIR)
	$(MAKE) build GOOS=linux GOARCH=386 O=$(RELEASE_DIR)

publish-release:
	gh release create $(RELEASE_TAG) --generate-notes $(RELEASE_DIR)/*

nexttag:
	$(if $(RELEASE_TAG),,$(eval RELEASE_TAG := $(shell $(NEXTTAG_CMD))))

.PHONY: build-release nexttag publish-release release tag-release

define NEXTTAG_CMD
{ git tag --list --merged HEAD --sort=-v:refname; echo v0.0.0; }
| grep -E "^v?[0-9]+.[0-9]+.[0-9]+$$"
| head -n1
| awk -F . '{ print $$1 "." $$2 "." $$3 + 1 }'
endef

# --- Utilities ----------------------------------------------------------------
COLOUR_NORMAL = $(shell tput sgr0 2>/dev/null)
COLOUR_RED    = $(shell tput setaf 1 2>/dev/null)
COLOUR_GREEN  = $(shell tput setaf 2 2>/dev/null)
COLOUR_WHITE  = $(shell tput setaf 7 2>/dev/null)

help:
	$(eval export HELP_AWK)
	@awk "$${HELP_AWK}" $(MAKEFILE_LIST) | sort | column -s "$$(printf \\t)" -t

$(O):
	@mkdir -p $@

.PHONY: help

# Awk script to extract and print target descriptions for `make help`.
define HELP_AWK
/^## / { desc = desc substr($$0, 3) }
/^[A-Za-z0-9%_-]+:/ && desc {
	sub(/::?$$/, "", $$1)
	printf "$(COLOUR_WHITE)%s$(COLOUR_NORMAL)\t%s\n", $$1, desc
	desc = ""
}
endef

define nl


endef
ifndef ACTIVE_HERMIT
$(eval $(subst \n,$(nl),$(shell bin/hermit env -r | sed 's/^\(.*\)$$/export \1\\n/')))
endif

# Ensure make version is gnu make 4.4 or higher (for .WAIT target)
ifeq ($(filter shell-export,$(value .FEATURES)),)
$(error Unsupported Make version. \
	$(nl)Use GNU Make 4.4 or higher (current: $(MAKE_VERSION)). \
	$(nl)Activate 🐚 hermit with `. bin/activate-hermit` and run again \
	$(nl)or use `bin/make`)
endif
