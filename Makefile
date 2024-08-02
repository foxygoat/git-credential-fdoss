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
	-rm -rf $(O) dist

.PHONY: all check-uptodate ci clean

# --- Build --------------------------------------------------------------------
GO_LDFLAGS = -X main.version=$(VERSION)
CMDS = .

## Build git-credential-fdoss binary
build: | $(O)
	go build -o $(O) -ldflags='$(GO_LDFLAGS)' $(CMDS)

## Build and install binaries in $GOBIN
install:
	go install -ldflags='$(GO_LDFLAGS)' $(CMDS)

## Tidy go modules with "go mod tidy"
tidy:
	go mod tidy

clean::

.PHONY: build install tidy

# --- Lint ---------------------------------------------------------------------
## Lint go source code
lint:
	golangci-lint run

.PHONY: lint

# --- Release -------------------------------------------------------------------
## Tag and release binaries for different OS on GitHub release
release: nexttag
	git tag $(RELEASE_TAG)
	git push origin $(RELEASE_TAG)
	goreleaser release --clean

nexttag:
	$(if $(RELEASE_TAG),,$(eval RELEASE_TAG := $(shell $(NEXTTAG_CMD))))

.PHONY: nexttag release

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

# Ensure make version is gnu make 3.82 or higher
ifeq ($(filter undefine,$(value .FEATURES)),)
$(error Unsupported Make version. \
	$(nl)Use GNU Make 3.82 or higher (current: $(MAKE_VERSION)). \
	$(nl)Activate 🐚 hermit with `. bin/activate-hermit` and run again \
	$(nl)or use `bin/make`)
endif
