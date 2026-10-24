##
## Copyright (c) 2023 whawty contributors (see AUTHORS file)
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions are met:
##
## * Redistributions of source code must retain the above copyright notice, this
##   list of conditions and the following disclaimer.
##
## * Redistributions in binary form must reproduce the above copyright notice,
##   this list of conditions and the following disclaimer in the documentation
##   and/or other materials provided with the distribution.
##
## * Neither the name of whawty.nginx-sso nor the names of its
##   contributors may be used to endorse or promote products derived from
##   this software without specific prior written permission.
##
## THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
## AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
## DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
## SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
## CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
## OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
## OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##

GOCMD := go
ifdef GOROOT
GOCMD = $(GOROOT)/bin/go
endif

EXECUTEABLE := whawty-nginx-sso

# the version printed by --version: the latest tag without the leading v, plus
# the number of commits since then and the commit if HEAD is not tagged
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null | sed -e 's/^v//')
LDFLAGS := $(if $(VERSION),-X main.version=$(VERSION))

all: build
.PHONY: format vet cover serve-cover clean distclean ui-icons

format:
	$(GOCMD) fmt ./...

vet:
	$(GOCMD) vet ./...

test: vet
	$(GOCMD) test `$(GOCMD) list ./...`

test-verbose: vet
	$(GOCMD) test -v `$(GOCMD) list ./...`

cover:
	mkdir -p ./.coverage
	$(GOCMD) test -v `$(GOCMD) list ./...` -covermode=count -coverprofile=./.coverage/profile
	$(GOCMD) tool cover -html=./.coverage/profile -o ./.coverage/index.html

serve-cover:
	cd ./.coverage; python3 -m http.server

build: test
	$(GOCMD) build -ldflags "$(LDFLAGS)" -o $(EXECUTEABLE) ./cmd/whawty-nginx-sso

dev: test
	$(GOCMD) build -ldflags "$(LDFLAGS)" -o $(EXECUTEABLE) -tags=dev ./cmd/whawty-nginx-sso

clean:
	rm -f $(EXECUTEABLE)

distclean: clean
	rm -f doc/man/$(EXECUTEABLE).8

# Icons of the web interface. `make ui-icons` downloads the npm packages
# lucide-static and @fortawesome/fontawesome-free and regenerates the sprite
# and the licenses from them. Without internet access, pass the directories of
# the unpacked packages: make ui-icons LUCIDE=<dir> FONTAWESOME=<dir>
# Icons starting with brand- are Font Awesome brand logos, all others Lucide icons.
UI_ICONS := bot circle-alert circle-check circle-help globe info log-in log-out monitor shield-house smartphone tablet triangle-alert \
            brand-android brand-apple brand-blackberry brand-chrome brand-edge brand-firefox-browser brand-freebsd \
            brand-internet-explorer brand-linux brand-opera brand-safari brand-windows
LUCIDE_VERSION := 1.59.0
LUCIDE_SHA256 := 39e2f835692c193233ac7bcdf34eb0cc2da0f839fd9f3674c34d2751bccf37f0
LUCIDE_URL := https://registry.npmjs.org/lucide-static/-/lucide-static-$(LUCIDE_VERSION).tgz
FONTAWESOME_VERSION := 7.3.1
FONTAWESOME_SHA256 := ca4e32843bd81711894385c2466fb19c55cfd32ef3c58830b2d1df7bd42e6571
FONTAWESOME_URL := https://registry.npmjs.org/@fortawesome/fontawesome-free/-/fontawesome-free-$(FONTAWESOME_VERSION).tgz
UI_ICONS_DIR := ui/assets/vendor

ui-icons:
ifdef LUCIDE
ifndef FONTAWESOME
	$(error FONTAWESOME must be set as well if LUCIDE is set)
endif
	$(GOCMD) run ui/tools/iconsprite.go -lucide $(LUCIDE) -fontawesome $(FONTAWESOME) -out $(UI_ICONS_DIR)/icons.svg $(UI_ICONS)
	cp $(LUCIDE)/LICENSE $(UI_ICONS_DIR)/lucide/LICENSE
	cp $(FONTAWESOME)/LICENSE.txt $(UI_ICONS_DIR)/fontawesome/LICENSE.txt
else
	tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	mkdir "$$tmp/lucide" "$$tmp/fontawesome" && \
	curl -fsSL -o "$$tmp/lucide.tgz" $(LUCIDE_URL) && \
	echo "$(LUCIDE_SHA256)  $$tmp/lucide.tgz" | sha256sum -c --quiet && \
	tar -xzf "$$tmp/lucide.tgz" -C "$$tmp/lucide" package/package.json package/LICENSE package/icons && \
	curl -fsSL -o "$$tmp/fontawesome.tgz" $(FONTAWESOME_URL) && \
	echo "$(FONTAWESOME_SHA256)  $$tmp/fontawesome.tgz" | sha256sum -c --quiet && \
	tar -xzf "$$tmp/fontawesome.tgz" -C "$$tmp/fontawesome" package/package.json package/LICENSE.txt package/svgs/brands && \
	$(MAKE) --no-print-directory ui-icons LUCIDE="$$tmp/lucide/package" FONTAWESOME="$$tmp/fontawesome/package"
endif

manpage: doc/man/$(EXECUTEABLE).8

doc/man/$(EXECUTEABLE).8: doc/man/$(EXECUTEABLE).8.txt
	a2x -f manpage $<
