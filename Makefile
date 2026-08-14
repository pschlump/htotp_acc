
.PHONY: all gen_version linux wsl test run_all gen_2fa_otk validate_otk get_list_sites import_qr_code register_001 install deploy

# gen_version regenerates version.go from the current git commit/tag/date.
gen_version:
	mkdir -p tmp
	git rev-list -1 HEAD >tmp/,ver
	echo "Tag: " >>tmp/,ver
	git tag --sort=v:refname | tail -1 >>tmp/,ver
	echo "Build Date: " >>tmp/,ver
	date >>tmp/,ver
	go run gen/main.go > version.go

all: gen_version
	go build

# linux/amd64 ELF (also runs under x86_64 WSL).
linux: gen_version
	GOOS=linux GOARCH=amd64 go build -o acc_linux

# Cross-compile for Jake's (jakce) x86_64 WSL development environment.
wsl: gen_version
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o acc_wsl

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

## git bump tag
git_set_tag:
	-git commit -a -m "Before Version Bump"
	-git push
	git tag v1.0.15
	git push origin --tags
	$(MAKE) all
	git add -A .
	-git commit -m "Version Bump"
	git push

