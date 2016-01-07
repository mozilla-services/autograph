# Autograph
Autograph is a cryptographic signature service that implements [Content-Signature](https://github.com/martinthomson/content-signature/) and other signing methods.

## Rationale
As we rapidly increase the number of services that send configuration data to Firefox agents, we also increase the probability of a service being compromised to serve fraudulent data to our users. Autograph implements a way to sign the information sent from backend services to Firefox user-agents, and protect them from a service compromise.

Digital signature adds an extra layer to the ones already provided by TLS and certificates pinning. As we grow our service infrastructure, the risk of a vulnerability on our public endpoints increases, and an attacker could exploit a vulnerability to serve bad data from trusted sites directly. TLS with certificate pinning prevents bad actors from creating fraudulent Firefox services, but does not reduce the impact a break-in would have on our users. Digital signature provides this extra layer.

Finally, digital signature helps us use Content Delivery Network without worrying that a CDN compromise would end-up serving bad data to our users. Signing at the source reduces the pressure off of the infrastructure and allows us to rely on vendors without worrying about data integrity.

## Architecture

### Signing

Autograph exposes a REST API that services can query to request signature of their data. Autograph knows which key should be used to sign the data of a service based on the service's authentication token. Access control and rate limiting are performed at that layer as well.

![signing.png](docs/statics/Autograph signing.png)

### Certificate issuance and renewal

Autograph signs data using ECDSA keys. The autograph public certs are signed by intermediate certs stored in HSMs, themselves signed by a Root CA stored offline. The Root CA is trusted in NSS, but for specific purposes only (eg. not signing website certs). Upon verification of a signature issued by Autograph, Firefox clients verify the full chain of trust against the root CAs, like any other PKI.

![signing.png](docs/statics/Autograph issuance.png)

Accessing the RootCA requires multiple people and a key ceremony, so we only do it every couple of years to reissue intermediate certificates. The intermediates are kept safely in HSMs where their private keys cannot be exported or stolen.

Every month-or-so, the autograph signers are refreshed with new certificates valid for only short period of time. Upon refresh, autograph calls the HSMs API with a CSR to obtain signed certificates. Those certificates are then stored in a public location when Firefox agents can retrieve them to verify signatures.

## API

Authorization: All API calls require a [hawk](https://github.com/hueniverse/hawk) Authorization header.

### POST /api/v1/sign
Request a signature on the body of the request. The data to sign must be encoded in base64 and submitted as `multipart/form-data` under the `b64data=` key.
```bash
curl -X POST -F "b64data=Y2FyaWJvdQo=" http://localhost:3000/api/v1/sign
```
Accepted parameters are:
* `hash` a base64 encoded hash. If specified, autograph will sign this value instead of hashing and signing the request body.
```bash
curl -X POST http://localhost:3000/api/v1/sign&hash=ZGIyMzhiZTQ3OWRjNzU5ZDQ2NGY4MDRhZGY2ZTVmZWJlNmRiNGYxYzRhYzRhZWYwN2IxYzZiNTVi=
```
* `keyid` an identifier of a signing key, if one must be specified (autograph will determine one otherwise).
```bash
curl -X POST -F "b64data=Y2FyaWJvdQo=" http://localhost:3000/api/v1/sign?keyid=newtab-prod-20160107
```
