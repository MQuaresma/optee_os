#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020, Miguel Quaresma

import sys
import datetime as dt
import math
from mbedtls import x509, pk
from mbedtls import hash as hashlib

USAGE = '''Usage: {} [options] [ <file> -t <encoding> ]
Options:
    -h Help
            
Supported encodings: pem, der
'''

CA_CRT_F='ca_cert.pem'
DC_CRT_F='dc_cert.pem'

def gen_ca_cert():
    ca_k = pk.ECC(b'secp256r1')
    _ = ca_k.generate()
    ca_csr = x509.CSR.new(ca_k, 'CN=Haslab', hashlib.sha256())
    now = dt.datetime.utcnow()
    ca_crt = x509.CRT.selfsign(ca_csr,
                               ca_k,
                               not_before=now,
                               not_after=now + dt.timedelta(days=90),
                               serial_number=0x1,
                               basic_constraints = x509.BasicConstraints(True, 1))

    with open(CA_CRT_F, 'w') as f:
        f.write(ca_crt.to_PEM())

    return ca_crt, ca_k


# TODO: encrypt dc key
def gen_dc(ca_crt, ca_k):
    dc_k = pk.ECC(curve=b'secp256r1')
    _ = dc_k.generate()
    dc_csr = x509.CSR.new(dc_k, 'CN=Haslab Device', hashlib.sha256())
    now = dt.datetime.utcnow()
    dc_crt = ca_crt.sign(dc_csr,
                         ca_k,
                         not_before=now,
                         not_after=now + dt.timedelta(days=90),
                         serial_number=0x1)

    with open(DC_CRT_F, 'w') as f:
        f.write(dc_crt.to_PEM())

    with open('dc_ak', 'wb') as f:
        dc_pk = dc_k.export_key('NUM')
        bl = math.ceil(dc_pk.bit_length()/8)
        f.write(dc_pk.to_bytes(bl,'little'))


def main():
    if len(sys.argv) > 1:
        if sys.argv[1] == '-h':
            print(USAGE.format(sys.argv[0]))
        else:
          ca_cert_f = sys.argv[1]
          fh = open(ca_cert_f, 'r')
          ca_crt = x509.CRT.from_file(fh)
          close(fh)
    else:
        print('Generating CA (root) certificate')
        ca_crt, ca_k = gen_ca_cert()
        print('CA certificate dumped in {}'.format(CA_CRT_F))
        
    print('Generating device certificate')
    gen_dc(ca_crt, ca_k)
    print('Device certificate dumped in {}'.format(DC_CRT_F))

    
if __name__ == "__main__":
    main()
