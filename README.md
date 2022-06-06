# acc - Demo Authenticator from Command Line.

`acc` is a full featured two factor authenticator.  It performs the same function as Google Authenticator
but can be run from the command line.   This is really useful for testing login that uses a two factor
authentication system.

The only supported hash is SHA1 at the moment.

Look in the ./Makefile for how to run the program.

## To build

```
$ go get
$ go build
```

## To run

Save the image of a QR code that is presented or do a screen capture of the QR code to a file.
Let's say that the QR code is saved to `~/Downloads/711210.png`.  Run the tool with the `--import` flag
to bring that in.

```
$ ./acc --import ~/Downloads/711210.png
```

This should create or append to an existing acc.cfg.json file.  It will also print out the name of the
account that this authenticates for.

You should be able to list the accounts and realms that are in the config file with:

```
$ ./acc --list
```

## To run with a secret

You can also import the secret itself.

```
$ ./acc --secret "16char-secret-value" --name "name that is is to beknow as" --username AUserToLoingWith  \
	--issuer domainIssuingThis.com 
```

## To generate a 2FA token

Given that you have an account `/app.example.com:demo5@gmail.com` you can generate the next
token for that account with:

```
$ ./acc --gen2fa "/app.example.com:demo5@gmail.com"
```

It will loop and show you how long you have left on the 2fa token.

The 2fa token is copied to the "clip board" so you should be able to paste it into some other application.


