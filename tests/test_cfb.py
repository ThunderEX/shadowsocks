import re
import binascii

from shadowsocks.crypto import openssl, sodium, mbedtls, cng

plain_text = b'This is a test for cfb mode.'
additional_plain = b'This is additional test for cfb mode.'


def test_cfb():
    for lib in (openssl, sodium, mbedtls, cng):
        lib_name = lib.__name__.split('.')[-1]
        load_funcs = [getattr(lib, func) for func in dir(lib) if func.startswith('load_') and lib_name in func]
        if len(load_funcs) != 1:
            raise NotImplementedError('There are not only one `load_libname` found in %s' % lib_name)
        try:
            load_funcs[0]()
            assert lib.loaded
        except Exception:
            print('can\'t load %s' % lib_name)
            continue

        for method in lib.ciphers:
            if not re.search('aes-\d+-cfb\d*', method, re.IGNORECASE):
                continue
            key_size, iv_size, kls = lib.ciphers[method]
            try:
                encryptor = kls(method, b'k' * key_size, b'i' * iv_size, 1)
            except Exception:
                print('can\'t load %s' % method)
                raise
            cipher_text = encryptor.encrypt(plain_text)
            cipher_additional = encryptor.encrypt(additional_plain)
            print(','.join([
                lib_name, method,
                binascii.hexlify(cipher_text[:4]).decode(),
                binascii.hexlify(cipher_additional[:4]).decode(),
            ]))
