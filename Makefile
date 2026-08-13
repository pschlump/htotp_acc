
.PHONY: all linux test run_all gen_2fa_otk validate_otk get_list_sites import_qr_code register_001 install deploy

all:
	mkdir -p tmp
	git rev-list -1 HEAD >tmp/,ver
	echo "Tag: " >>tmp/,ver
	git tag --sort=v:refname | tail -1 >>tmp/,ver
	echo "Build Date: " >>tmp/,ver
	date >>tmp/,ver
	go run gen/main.go > version.go
	go build

linux:
	GOOS=linux GOARCH=amd64 go build -o acc_linux

test:
	go vet ./...
	go test ./...

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


#InitialSetup:
#	echo "# htotp_acc" >> README.md
#	git init
#	git add README.md
#	git commit -m "first commit"
#	git branch -M main
#	git remote add origin https://github.com/pschlump/htotp_acc.git
#	git push -u origin main


## git bump tag
git_set_tag:
	git commit -a -m "Before Version Bump"
	git push 
	git tag v1.0.10
	git push origin --tags
	git add -A .
	git commit -m "Version Bump"

