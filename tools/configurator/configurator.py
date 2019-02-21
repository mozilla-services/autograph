#!/usr/bin/env python3


import argparse
import re
import os
import sys

from ruamel import yaml


SIGNER_CONFIG_PARAMS = ["type", "mode", "privatekey", "publickey",
                        "certificate", "x5u", "keyid", "passphrase",
                        "validity", "clock_skew_tolerance",
                        "chain_upload_location", "cacert"]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    optional = parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')

    required.add_argument('-c', dest="autograph_config", type=str,
                          default="autograph.yaml",
                          help='path to a decoded autograph YAML config')

    required.add_argument('-s', type=str, dest="signer_id",
                          help='id of the signer configuration to modify')

    required.add_argument('-p', type=str, dest="parameter",
                          help='name of the config parameter to set, '
                          'should be one of: ' +
                          ' '.join(str(p) for p in SIGNER_CONFIG_PARAMS))

    required.add_argument('-v', type=str, dest="value",
                          help='value of the config parameter. if this is '
                          'a path, the file is read and its content used'
                          'as value')

    optional.add_argument('-i', dest="in_place", action='store_true',
                          help='modifies the config in place')

    optional.add_argument('-o', dest="output_config", type=str,
                          default="stdout",
                          help='output modified config to <output_config>')

    parser._action_groups.append(optional)
    return parser.parse_args()


def main():
    args = parse_args()

    if args.parameter not in SIGNER_CONFIG_PARAMS:
        print("-p must be one of: " + ' '.join(str(p)
                                               for p in SIGNER_CONFIG_PARAMS))
        sys.exit(1)

    if args.autograph_config == args.output_config:
        if not args.in_place:
            print("use -i to overwrite a configuration file in place")
            sys.exit(3)

    with open(args.autograph_config, 'r') as config_in:
        config = yaml.load(config_in, Loader=yaml.RoundTripLoader)

    try:
        os.stat(args.value)
        with open(args.value) as data:
            args.value = data.read()
    except FileNotFoundError:
        pass

    # Loop over the config, find a signer that matches the ID we want
    # then set or replace the parameter with the provided value
    found = False
    for signer in config['signers']:
        if signer['id'] == args.signer_id:
            found = True
            signer[args.parameter] = args.value

    if not found:
        print("signer id %s not found" % (args.signer_id))
        sys.exit(2)

    if args.in_place:
        print("overwriting %s" % (args.autograph_config))
        args.output_config = args.autograph_config
    if args.output_config == "stdout":
        yaml.dump(config, sys.stdout, Dumper=yaml.RoundTripDumper)
    else:
        with open(args.output_config, 'w') as config_out:
            yaml.dump(config, config_out, Dumper=yaml.RoundTripDumper)


if __name__ == '__main__':
    main()
