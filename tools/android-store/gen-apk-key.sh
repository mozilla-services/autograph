#!/usr/bin/env bash

# generate artifacts for a new Android application
USAGE="usage: ${0##*/} [options] app_name
Generate signing key and Play Store artifacts for an Android application

Note: While this script can be run standalone, it can produce more artifacts if
      run in a context with some java tooling available. See
      https://mozilla-hub.atlassian.net/wiki/spaces/SECENGOPS/pages/408978175/Adding+a+new+APK+signing+key
      for details.

Positional Arguments:
    app_name        Name of Android app to be placed in certificate. Required.

Options:
    --certificate   Existing certificate to use for wrapping
    --key           Existing key to use for wrapping
    --no-pepk       Do not generate the '.pepk' file needed by Google Play
    --pepk          Specify pepk.jar path (default ../pepk.jar)
    --wrap-key      App specific wrap key to use with 'pepk'
                    Defaults to '../encryption_public_key.pem'
    -h|--help       output this help
"

set -eu

warn() { for m; do echo "$m"; done 1>&2 ; }
die() { warn "$@" ; exit 2; }
usage() { warn "$@" "${USAGE:-}" ; [[ $# == 0 ]] && exit 0 || exit 1;}

gen_key=true
gen_cert=true
private_key=""      # no key signifies to generate one
certificate=""
use_pepk=true
wrap_key=../encryption_public_key.pem
pepk=../pepk.jar

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --certificate) gen_cert=false ; certificate="$2" ; shift ;;
        --key) gen_key=false ; private_key="$2" ; shift ;;
        --no-pepk) use_pepk=false ;;
        --pepk) pepk="$2" ; shift ;;
        --wrap-key) wrap_key="$2" ; shift ;;
        -h|--help) usage ;;
        -*) usage "Unknown option '$1'" ;;
        *) break ;;
    esac
    shift
done

# Now have non-option args
test $# -eq 1 || usage "Wrong number of args"
app_name="$@"

# check for files if specified
${gen_key} || { ! [[ -r "${private_key}" ]] && usage "Can't find private key '${private_key}'" ; }
${gen_cert} || { ! [[ -r "${certificate}" ]] && usage "Can't find certificate '${certificate}'" ; }
${gen_key} && ! ${gen_cert} && usage "You must supply a private key when supplying a certificate."

# check for tooling for pepk, if requested
if ${use_pepk} ; then
    ! [[ -r ${pepk} ]] && usage "Can't find utility 'pepk.jar'. (Do you want the '--no-pepk' option?)"
    ! [[ -r ${wrap_key} ]] && usage "Can't find wrap key '${wrap_key}'."
    # the output format of pepk depends on whether or not we need to include the
    # certificate. We do if we're not reusing an existing certificate.
    if ${gen_cert} ; then
        pepk_file_extension="zip"
        pepk_include_cert_option="--include-cert"
    else
        pepk_file_extension="pepk"
        pepk_include_cert_option=""
    fi
fi


# setup defaults
CN="${app_name}"
OU="Release Engineering"
O="Mozilla Corporation"
L="San Francisco"
ST="California"
C="US"

# build arguments to openssl
subject="/CN=$CN/OU=$OU/O=$O/L=$L/ST=$ST/C=$C"
if $gen_key ; then
    private_key="${app_name}"-private-key.pem
    key_option='-newkey rsa:2048 -nodes -keyout'
else
    key_option='-key'
fi

# Generate keys & certificate
if ${gen_cert} ; then
    openssl req -x509 \
        ${key_option} "${private_key}" \
        -subj "${subject}" \
        -extensions "usr_cert" \
        -days 10000 \
        -out "${app_name}"-signing-cert.pem \
        2>/dev/null
else
    # only need to copy the cert to the expected name - fails if already named
    # that, so ignore any error (we know it's readable from above)
    cp "${certificate}" "${app_name}"-signing-cert.pem 2>/dev/null || true
fi
openssl rsa -pubout -in "${private_key}" > "${app_name}"-public-key.pem

cat <<EOS
Produced key artifacts for $app_name:
    Certificate: $($gen_cert || echo "(copied existing)") ${app_name}-signing-cert.pem
$( # Get the certificate dates (since this has caused a bug)
    openssl x509 -in "${app_name}"-signing-cert.pem -noout -text\
    | grep -E '((Not (After |Before))|Issuer):' )
    Private Key: $($gen_key || echo "(used existing)") ${private_key}
    Public Key:  ${app_name}-public-key.pem
EOS

# Now generate the 'pepk' format if requested
if ${use_pepk} ; then
    playstore_upload_file="${app_name}.${pepk_file_extension}"
    rm -f temp.keystore "${playstore_upload_file}"
    openssl pkcs12 -export \
        -caname root -passout pass:def \
        -in "${app_name}"-signing-cert.pem -inkey "${private_key}" \
        -out temp.p12 -name "${app_name}" -CAfile ca.crt

    keytool -importkeystore \
        -srckeystore temp.p12 -srcstoretype PKCS12 -srcstorepass "def" \
        -deststorepass abcdef -destkeypass abcdef -destkeystore temp.keystore \
        -alias "${app_name}"

    #Create the wrapped key

    echo use abcdef as the password when prompted
    java -jar ${pepk} \
            --rsa-aes-encryption \
            --keystore=temp.keystore \
            --alias="${app_name}" \
            ${pepk_include_cert_option} \
            --encryption-key-path="${wrap_key}" \
            --output="${playstore_upload_file}"
    # Double check we got a zip file, if that's whate we expected
    if [[ ${pepk_file_extension} == "zip" ]] \
            && ! file "${playstore_upload_file}" | grep "Zip archive data" &>/dev/null ; then
        die "ERROR: Did not generate an expected pepk zip file: '${playstore_upload_file}'"
    else
        echo "    PEPK file:   ${playstore_upload_file}"
    fi

    # cleanup
    test -w "${private_key}" && chmod a+r "${private_key}"  # Make sure private signing key is readable outside of docker 
    rm -f temp.p12 temp.keystore
fi
