# Autograph
A signing service that implements [Content-Signature](https://github.com/martinthomson/content-signature/) and other signing methods.

## Rationale
As we rapidly increase the number of services that send configuration data to Firefox agents, we also increase the probability of a service being compromised to serve fraudulent data to our users. Autograph implements a way to sign the information sent from backend services to Firefox user-agents, and protect them from a service compromise.

Digital signature adds an extra layer to the ones already provided by TLS and certificates pinning. As we grow our service infrastructure, the risk of a vulnerability on our public endpoints increases, and an attacker could exploit a vulnerability to serve bad data from trusted sites directly. TLS with certificate pinning prevents bad actors from creating fraudulent Firefox services, but does not reduce the impact a break-in would have on our users. Digital signature provides this extra layer.

Finally, digital signature helps us use Content Delivery Network without worrying that a CDN compromise would end-up serving bad data to our users. Signing at the source reduces the pressure off of the infrastructure and allows us to rely on vendors without worrying about data integrity.

## Architecture

### Signing

Autograph exposes a REST API that services can query to request signature of their data. Autograph knows which key should be used to sign the data of a service based on the service's authentication token. Access control and rate limiting are performed at that layer as well.

![signing.png](docs/statics/Autograph signing.png)


### Certificate issuance

Autograph signs data using ECDSA keys. The associated public keys are signed by intermediate certs stored in HSMs. The private key of the root CA that signs those intermediates is stored offline, and the public cert is stored in NSS. Upon verification of a signature issued by Autograph, clients verify the full chain of trust against the root CAs, like any other PKI.

![signing.png](docs/statics/Autograph issuance.png)
