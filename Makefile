
.PHONY: all linux wsl test run_all gen_2fa_otk validate_otk get_list_sites import_qr_code register_001 install deploy

# Build information (git commit, tag, build date) is injected at link time via
# -ldflags; version.go is static and never regenerated.
LDFLAGS := -X 'main.GitCommit=$(shell git rev-list -1 HEAD)' \
           -X 'main.GitTag=$(shell git tag --sort=v:refname | tail -1)' \
           -X 'main.BuildDate=$(shell date)'

all:
	go build -ldflags "$(LDFLAGS)"

# linux/amd64 ELF (also runs under x86_64 WSL).
linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o acc_linux

# Cross-compile for Jake's (jakce) x86_64 WSL development environment.
wsl:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o acc_wsl

test:
	go vet ./...
	go test ./...
	$(MAKE) bash-tests

## bash-tests: run the bash test suite in ./tests (builds acc into a temp dir;
## uses UWCedar.png - a defunct site - as QR test data)
bash-tests:
	bash tests/run-tests.sh

# This is kind of a full run of what the CLI Authenticator can do.
run_all: import_qr_code gen_2fa_otk validate_otk get_list_sites

validate_otk:
	mkdir -p ./out
	./acc --get2fa "/www.2c-why.com:pschlump@gmail.com" --output ./out/,otk
	./acc --get2fa "/www.2c-why.com:pschlump@gmail.com" --verify `cat ./out/,otk`
	rm -f ./out/,otk

get_list_sites:
	./acc --list

import_qr_code:
	./acc --import test1.png

register_001:
	./acc --import xyzzy.png

install:
	( cd ~/bin ; rm -f acc )
	( cd ~/bin ; ln -s ../go/src/github.com/pschlump/htotp_acc/acc . )

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## git bump tag: tag HEAD with the next patch version (v1.0.N -> v1.0.N+1) and
## push it.  The build picks the tag up via the -X flag above; version.go no
## longer changes on a build so there is no "Version Bump" commit to make.
git_set_tag:
	-git commit -a -m "Before Version Bump"
	-git push
	git tag "$$(git tag --sort=v:refname | tail -1 | awk -F. '{print $$1"."$$2"."$$3+1}')"
	git push origin --tags

