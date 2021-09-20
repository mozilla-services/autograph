module github.com/mozilla-services/autograph

go 1.16

require (
	github.com/Azure/azure-sdk-for-go v32.6.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/adal v0.8.0 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/DataDog/datadog-go v3.7.2+incompatible
	github.com/ThalesIgnite/crypto11 v0.1.0
	github.com/aws/aws-lambda-go v1.26.0
	github.com/aws/aws-sdk-go v1.40.45
	github.com/golang/mock v1.6.0
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/lib/pq v1.10.3
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/mattn/go-isatty v0.0.10 // indirect
	github.com/miekg/pkcs11 v1.0.3
	github.com/mozilla-services/autograph/verifier/contentsignature v0.0.0-20210505200649-cb56f0dcbdd1
	github.com/mozilla-services/yaml v0.0.0-20191106225358-5c216288813c
	github.com/sirupsen/logrus v1.8.1
	github.com/youtube/vitess v2.1.1+incompatible // indirect
	go.mozilla.org/cose v0.0.0-20200221144611-2ea72a6b3de3
	go.mozilla.org/hawk v0.0.0-20190327210923-a483e4a7047e
	go.mozilla.org/mar v0.0.0-20200124173325-c51ce05c9f3d
	go.mozilla.org/mozlogrus v2.0.0+incompatible
	go.mozilla.org/pkcs7 v0.0.0-20210730143726-725912489c62
	go.mozilla.org/sops v0.0.0-20190912205235-14a22d7a7060
	go.opencensus.io v0.22.1 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 // indirect
	google.golang.org/api v0.11.0 // indirect
	google.golang.org/grpc v1.24.0 // indirect
)

replace github.com/mozilla-services/autograph/verifier => ./verifier/
