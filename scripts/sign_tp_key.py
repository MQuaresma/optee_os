#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020, Miguel Quaresma
#


import sys



def get_args(logger):
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument('--uuid', required=True,
                        help='String UUID of the TA')
    parser.add_argument('--master_key', required=True,
                        help='Name of the signing key (PEM format)')
    parser.add_argument('--tp_key', required=True,
                        help='Name of the third party key (PEM format)')
    parser.add_argument('--tp_key_type', required=False,
                        help='Type of the third party key (e.g. ECDSA or RSA)')

    parsed = parser.parse_args()

    if not(parsed.tp_key_type):
        parsed.tp_key_type = 'rsa'
        logger.warn('No third party key type provided, assuming RSA...')

    return parsed


def proc_rsa_key(key):
    #FIXME
    return bytes(key)

def proc_ecdsa_key(key):
    #FIXME
    return bytes(key)    


def main():
    from Cryptodome.Signature import pss
    from Cryptodome.Hash import SHA256
    from Cryptodome.PublicKey import RSA, ECC
    import os
    import logging
    import sys

    logging.basicConfig()
    logger = logging.getLogger(os.path.basename(__file__))

    args = get_args(logger)

    with open(args.master_key, 'rb') as f:
        master_key = RSA.import_key(f.read())

    with open(args.tp_key, 'rb') as f:
        if args.tp_key_type == 'rsa':
            tp_key = RSA.import_key(f.read())
            tp_key_raw = proc_rsa_key(tp_key)
        elif args.tp_key_type == 'ecdsa':
            tp_key = ECC.import_key(f.read())
            tp_key_raw = proc_ecdsa_key(tp_key)
        else:
            logger.error('Invalid key format')
            sys.exit(1)  

    h = SHA256.new()
    h.update(tp_key_raw)
    md = h.digest()


    if master_key.has_private():
        signer = pss.new(master_key)
        sig = signer.sign(md)

        with open(args.uuid + '.crt', 'wb') as f:
            f.write(sig)
            f.write(tp_key_raw)
    else:
        logger.error('Provided key can\'t be used for signign')
        sys.exit(1)


if __name__ == "__main__":
    main()
