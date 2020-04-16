#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2020, Miguel Quaresma

import sys, math, re, os
import datetime as dt
from mbedtls import x509, pk, hmac, cipher
from mbedtls import hash as hashlib


USAGE = '''Usage: {} [options] [ <file> -t <encoding> ]
Options:
    -h Help
            
Supported encodings: pem, der
'''

CA_CRT_F='ca_cert.pm'
DC_F='dc'
AK_F='ak'
OUT_DIR='dc_files'

def gen_ca_cert():
    ''' Generate CA certificate to emulate the device manufacturer
    '''
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

    ca_crt_fp = os.path.join(OUT_DIR, CA_CRT_F)
    with open(ca_crt_fp, 'w') as f:
        f.write(ca_crt.to_PEM())

    return ca_crt, ca_k


def encrypt_pk(dc_pk):
    ''' Encrypt the attestation key with the hardcoded sub hardware
    key
    '''
    m = hmac.sha256(b'\x00'*16)
    m.update(int.to_bytes(5, 4, 'little', signed=False))
    huk_subkey = m.digest()[:16]
    e = cipher.AES.new(huk_subkey, cipher.MODE_CTR, b'\x00'*16)
    return e.encrypt(dc_pk)


def format(raw):
    ''' Format an hex string according to C char arrays
    '''
    c_var = '"{}" \\\n'

    proc = re.sub(r'([0-9a-f]{2})', r'\\x\1', raw)
    lines = re.findall(r'(.{2,56})', proc)
    proc = ''

    for line in lines[:-1]:
        proc = proc + c_var.format(line)
    proc += '"{}";'.format(lines[-1])

    return proc


def gen_dc(ca_crt, ca_k):
    ''' Generate the device certificate, signed by the manufacturer
    '''
    ak = pk.ECC(curve=pk.Curve.SECP256R1)
    _ = ak.generate()
    dc_csr = x509.CSR.new(ak, 'CN=Haslab Device', hashlib.sha256())
    now = dt.datetime.utcnow()
    dc_crt = ca_crt.sign(dc_csr,
                         ca_k,
                         not_before=now,
                         not_after=now + dt.timedelta(days=90),
                         serial_number=0x1)

    # Device certificate
    dc_der = dc_crt.to_DER()
    c_dc = format(dc_der.hex())

    # Signing key
    ak = ak.export_key('NUM')
    bl = math.ceil(ak.bit_length()/8)
    ak_raw = ak.to_bytes(bl,'little')
    c_ak_txt = format(ak_raw.hex())

    # Encrypted attestation key
    ak_enc = encrypt_pk(ak_raw).hex()
    c_ak_enc = format(ak_enc)

    c_dc_ak = format(dc_der.hex() + ak_enc)

    with open(os.path.join(OUT_DIR, DC_F + '.der'), 'wb') as f:
        f.write(dc_der)
    with open(os.path.join(OUT_DIR, AK_F + '.txt'), 'w') as f:
        f.write(c_ak_txt)

    with open(os.path.join(OUT_DIR, DC_F + '.var'), 'w') as f:
        f.write(c_dc)
    with open(os.path.join(OUT_DIR, AK_F + '.var'), 'w') as f:
        f.write(c_ak_enc)
    with open(os.path.join(OUT_DIR, DC_F + AK_F + '.var'), 'w') as f:
        f.write(c_dc_ak)

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
        os.mkdir(OUT_DIR)
        print('Generating CA (root) certificate')
        ca_crt, ca_k = gen_ca_cert()
        print('CA certificate dumped in {}'.format(CA_CRT_F))
        
    print('Generating device certificate')
    gen_dc(ca_crt, ca_k)
    print('Device certificate dumped in {}'.format(DC_F + '.der'))

    
if __name__ == "__main__":
    main()
