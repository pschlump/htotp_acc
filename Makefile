
all:
	mkdir -p tmp
	git rev-list -1 HEAD >tmp/,ver
	echo "Tag: " >>tmp/,ver
	git tag | tail -1 >>tmp/,ver
	echo "Build Date: " >>tmp/,ver
	date >>tmp/,ver
	go run gen/main.go > version.go
	go build

linux:
	GOOS=linux GOARCH=amd64 go build -o acc_linux

# This is kind of a full run of what the CLI Authenticator can do.
run_all: import_qr_code gen_2fa_otk validate_otk get_list_sites

gen_2fa_otk:
	./acc --get2fa "/www.2c-why.com:pschlump@gmail.com"

validate_otk:
	mkdir -p ./out
	./acc --get2fa "/www.2c-why.com:pschlump@gmail.com" --output ./out/,otk
	./acc --get2fa "/www.2c-why.com:pschlump@gmail.com" --verify `cat ./out/,otk`

get_list_sites:
	./acc --list

import_qr_code:
	./acc --import test1.png

register_001:
	./acc --import xyzzy.png

install:
	cp acc ~/bin


InitialSetup:
	echo "# htotp_acc" >> README.md
	git init
	git add README.md
	git commit -m "first commit"
	git branch -M main
	git remote add origin https://github.com/pschlump/htotp_acc.git
	git push -u origin main


deploy: linux
	scp acc_linux philip@45.79.53.54:/home/philip/tmp/acc
