Add-on Signer
===================

**Warning: Python 3 only!**

This script takes an XPI, submits it to the specified autograph service for signature, and overwrites the original XPI with a signed one.

## Requirements ##

The following system packages need to be install before you begin:
```
git
pip
python3
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

$ python sign.py \
    -t http://localhost:8000/sign/data \
    -s webextensions-rsa \
    -u alice \
    -p fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu \
    test-addon.xpi

some_extension.xpi signed!
```
