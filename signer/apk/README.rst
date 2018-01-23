APK Signing
===========

To generate a key and certificate using the standard `keytool` approach, use the
following command:

.. code:: bash

    keytool -keystore testkeystore.jks -genkey -alias testapp -keysize 2048 -keyalg RSA -validity 10000 -keypass password1 -storepass password1

This will create a file called `testkeystore.jks` that contains both the private
RSA key and the public certificate. To export these in PEM format and load them
into the Autograph configuration, we first need to export the keystore into
PKCS12, then extract the private key from the PKCS12 file, as follows:

.. code:: bash

    # export the keystore into pkcs12
    keytool -importkeystore -srckeystore testkeystore.jks -destkeystore testkeystore.p12 -deststoretype PKCS12 -srcalias testapp -deststorepass password1 -destkeypass password1

    # export the private key from the pkcs12 file into PEM
    openssl pkcs12 -in testkeystore.p12  -nodes -nocerts -out key.pem
    
    # export the public certificate from the keystore into PEM
    keytool -exportcert -keystore testkeystore.jks -alias testapp|openssl x509 -inform der -text
