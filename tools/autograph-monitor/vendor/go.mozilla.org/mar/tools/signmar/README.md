# Firefox's SignMar

This is a distribution of the `signmar` tool that is part of Firefox and gets
automatically built with it. This particular version was compiled on ArchLinux
and runs fine in Ubuntu Trusty (for TravisCI), you just need to set
LD_LIBRARY_PATH to the `lib` directory for it to find `libmozsqlite`.

Here's how to use it to verify a MAR signature:

1. Sign a random MAR file using `examples/sign.go`:

```bash
$ go run examples/sign.go firefox-60.0esr-60.0.1esr.partial.mar /tmp/resigned.mar
--- MAR file has been resigned ---
rsa cert written to /tmp/ea89c90a7031ec69f7ca7666ee4448bcc6c20c6a7aa86bfee0cb7f10baafd764.der
```

2. Create a directory for the NSS DB and import the signing cert:

```bash
$ mkdir /tmp/nssdb
$ certutil -d /tmp/nssdb -A -i /tmp/ea89c90a7031ec69f7ca7666ee4448bcc6c20c6a7aa86bfee0cb7f10baafd764.der -n "testmar" -t ",,u"
$ tree /tmp/nssdb/
/tmp/nssdb/
├── cert9.db
├── key4.db
└── pkcs11.txt

0 directories, 3 files
```

3. Invoke signmar to verify the MAR signature

```bash
$ LD_LIBRARY_PATH=lib/ ./signmar -d /tmp/nssdb/ -n testmar -v /tmp/resigned.mar
$ echo $?
0
```

If it succeeds, zero is returned. Otherwise, the error `ERROR: Error verifying
signature.` is printed.
