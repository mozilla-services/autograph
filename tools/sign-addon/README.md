Add-on Signer
===================

This script takes an unsigned XPI, submits it to the specified autograph
service, and overwrites the unsigned XPI with a signed one.

## Requirements ##

The following system packages need to be install before you begin:
```
git
pip
python
swig (for M2Crypto)
virtualenv
```

## Installation ##
```bash
$ virtualenv venv
$ source ./venv/bin/activate
$ pip install -r requirements.txt
```

## Usage ##
```bash
$ source ./venv/bin/activate

$ python sign.py -t https://some.autograph.endpoint.com/sign/data -s extension_rsa -u addon_shipper -p **** some_extension.xpi

some_extension.xpi signed!
```

### Swig + M2Crypto on OSX ###
I ran into issues getting M2Crypto to build on OSX. Use the following brew formula to get it working:
```
brew uninstall swig --force
brew install homebrew/versions/swig304
brew link homebrew/versions/swig304
```
