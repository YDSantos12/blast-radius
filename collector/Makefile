BINARY  := blast-radius-collector
DISTDIR := dist
PKG     := ./cmd/collector

.PHONY: all build-windows build-macos build-macos-arm

all: build-windows build-macos build-macos-arm

build-windows:
	@mkdir -p $(DISTDIR)
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
		-o $(DISTDIR)/$(BINARY)-windows-amd64.exe $(PKG)

build-macos:
	@mkdir -p $(DISTDIR)
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
		-o $(DISTDIR)/$(BINARY)-darwin-amd64 $(PKG)

build-macos-arm:
	@mkdir -p $(DISTDIR)
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" \
		-o $(DISTDIR)/$(BINARY)-darwin-arm64 $(PKG)
