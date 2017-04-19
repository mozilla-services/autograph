=============
Configuration
=============

.. sectnum::
.. contents:: Table of Contents

The configuration lives in `autograph.yaml` and is expected in
`/etc/autograph/autograph.yaml` (use flag `-c` to provide an alternate
location).

Listener
--------

Define an address and port for the API to listen on:

.. code:: yaml

	server:
		listen: "192.168.1.28:8000"


Signers
-------

The configuration for each signer is described in their respective README.

* `Content-Signature`_
* `XPI`_

.. _`Content-Signature`: https://github.com/mozilla-services/autograph/blob/master/signers/contentsignature/README.rst

.. _`XPI`: https://github.com/mozilla-services/autograph/blob/master/signers/xpi/README.rst

Authorizations
--------------

Authorizations map an arbitrary username and key to a list of signers. The
key does not need to be generated in any special way, but you can use the tool
in `tools/maketoken/main.go` to obtain a random 256bits string:

.. code:: bash

	$ openssl rand -hex 32
	ecf1dbcf7d8b161f51d7f590ea4a4eec8332918276ddcfc657fb0b863b2e37e7

Then add it to the configuration as follows:

.. code:: yaml

	authorizations:
		- id: alice
		  key: fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu
		  signers:
			  - appkey1
			  - appkey2
		- id: bob
		  key: 9vh6bhlc10y63ow2k4zke7k0c3l9hpr8mo96p92jmbfqngs9e7d
		  signers:
			  - appkey2

The configuration above allows `alice` to request signatures from both `appkey1`
and `appkey2`, while `bob` is only allowed to request signatures from `appkey2`.

Note that, when a user is allowed to sign with more than one signer, and no
specific signer key id is provided in the signing request, autograph will use
the first signer in the list. For example, if alice requests a signature without
providing a key id, the private key from `appkey1` will be used to sign her
request.

Build and running
-----------------

Build the autograph binary using make:

.. code:: bash

	$ make

The binary is located in `$GOPATH/bin/autograph` and can be started with the
configuration file:

.. code:: bash

	$ $GOPATH/bin/autograph -c autograph.yaml 
	{"Timestamp":1453721399358695130,"Type":"app.log","Logger":"Autograph","Hostname":"gator1","EnvVersion":"2.0","Pid":17287,"Fields":{"msg":"main.go:74: Starting Autograph API on localhost:8000"}}


You can test that the API is alive by querying its heartbeat URL:

.. code:: bash

	$ curl localhost:8000/__heartbeat__
	ohai

Test Key/Cert
-------------

For dev and testing purposes, the private key `appkey1` can be used with the
following self-signed certificate:

 ::

	-----BEGIN CERTIFICATE-----
	MIICjjCCAhUCCQC92fl+HNcL+zAKBggqhkjOPQQDAjCBsDELMAkGA1UEBhMCVVMx
	EzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxHDAa
	BgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xFzAVBgNVBAsTDkNsb3VkIFNlcnZp
	Y2VzMRYwFAYDVQQDEw1BdXRvZ3JhcGggRGV2MSUwIwYJKoZIhvcNAQkBFhZob3N0
	bWFzdGVyQG1vemlsbGEuY29tMB4XDTE2MDIwNjAwMDYwMloXDTI2MDIwMzAwMDYw
	MlowgbAxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
	Ew1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMRcw
	FQYDVQQLEw5DbG91ZCBTZXJ2aWNlczEWMBQGA1UEAxMNQXV0b2dyYXBoIERldjEl
	MCMGCSqGSIb3DQEJARYWaG9zdG1hc3RlckBtb3ppbGxhLmNvbTB2MBAGByqGSM49
	AgEGBSuBBAAiA2IABOJNxZhu3RaDrd07s5e+mm00bSvLG/6/4mwknlSmvekW6zl9
	nIrHM/00/MH6gWEv/HDeMzHtfn+8EZpDawlKI2UdWSpmDNgXolDjJTKKpNju/rsL
	J9Q8DUEmD+fE5L2bejAKBggqhkjOPQQDAgNnADBkAjARjtum9oq77JL9fhZ46Q1S
	vxT5RAdzQRp9/l3OqnUP+kK42tRk05c9UGDFXLLVH/4CMH/ZmcpvtM0sCjeAWzGs
	gnw91z0443965WZmaeBKpbinxB1PpnNMCnPhd9J/Hz40+Q==
	-----END CERTIFICATE-----
