from __future__ import absolute_import, division, print_function, \
    with_statement

from ctypes import (
    c_char_p, c_int, c_long, byref, create_string_buffer, c_void_p, c_byte,
    c_ulong, c_wchar_p, c_ubyte, POINTER, sizeof, cast
)
try:
    from ctypes.wintypes import (
        BYTE, LONG, ULONG, DWORD,
        LPCWSTR,
        HANDLE,
    )
except ValueError:
    BYTE = c_byte
    LONG = c_long
    ULONG = c_ulong
    DWORD = c_ulong
    LPCWSTR = c_wchar_p
    HANDLE = c_void_p

from shadowsocks.crypto import util

PUCHAR = POINTER(c_ubyte)
PBYTE = POINTER(BYTE)

#
# bcrypt.h
#
NTSTATUS = LONG
BCRYPT_HANDLE = HANDLE
BCRYPT_ALG_HANDLE = HANDLE
BCRYPT_KEY_HANDLE = HANDLE

# BCrypt String Properties
BCRYPT_OBJECT_LENGTH = 'ObjectLength'
BCRYPT_CHAINING_MODE = 'ChainingMode'
BCRYPT_BLOCK_LENGTH = 'BlockLength'
BCRYPT_MESSAGE_BLOCK_LENGTH = 'MessageBlockLength'

BCRYPT_CHAIN_MODE_NA = 'ChainingModeN/A'
BCRYPT_CHAIN_MODE_CBC = 'ChainingModeCBC'
BCRYPT_CHAIN_MODE_ECB = 'ChainingModeECB'
BCRYPT_CHAIN_MODE_CFB = 'ChainingModeCFB'
BCRYPT_CHAIN_MODE_CCM = 'ChainingModeCCM'
BCRYPT_CHAIN_MODE_GCM = 'ChainingModeGCM'

# BCrypt Flags
BCRYPT_BLOCK_PADDING = 0x00000001

# Common algorithm identifiers.
BCRYPT_AES_ALGORITHM = 'AES'

_func = (
    # Primitive algorithm provider functions.
    ('BCryptOpenAlgorithmProvider', (POINTER(BCRYPT_ALG_HANDLE), LPCWSTR, LPCWSTR, ULONG), NTSTATUS),
    # ('BCryptGetProperty', (BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, POINTER(ULONG), ULONG), NTSTATUS),
    # ('BCryptSetProperty', (BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG), NTSTATUS),
    ('BCryptCloseAlgorithmProvider', (BCRYPT_ALG_HANDLE, ULONG), NTSTATUS),
    # Primitive encryption functions.
    # ('BCryptGenerateSymmetricKey', (BCRYPT_ALG_HANDLE, POINTER(BCRYPT_KEY_HANDLE), PUCHAR, ULONG, PUCHAR, ULONG, ULONG), NTSTATUS),
    # ('BCryptEncrypt', (BCRYPT_KEY_HANDLE, PUCHAR, ULONG, c_void_p, PUCHAR, ULONG, PUCHAR, ULONG, POINTER(ULONG), ULONG), NTSTATUS),
    # ('BCryptDecrypt', (BCRYPT_KEY_HANDLE, PUCHAR, ULONG, c_void_p, PUCHAR, ULONG, PUCHAR, ULONG, POINTER(ULONG), ULONG), NTSTATUS),
    # ('BCryptDestroyKey', (BCRYPT_KEY_HANDLE,), NTSTATUS),
)

bcrypt = None
loaded = False

buf = None
buf_size = 2048


def load_bcrypt(crypto_path=None):
    from ctypes import windll
    global loaded, bcrypt, buf

    bcrypt = windll.bcrypt

    for func_name, argtypes, restype in _func:
        if hasattr(bcrypt, func_name):
            getattr(bcrypt, func_name).argtypes = argtypes
            getattr(bcrypt, func_name).restype = restype

    buf = create_string_buffer(buf_size)
    loaded = True


class BcryptCryptBase(object):
    """
    bcrypt crypto base class
    """
    def __init__(self, cipher_name, crypto_path=None):
        if not loaded:
            load_bcrypt(crypto_path)
        self._alg_handle = HANDLE()
        res = bcrypt.BCryptOpenAlgorithmProvider(byref(self._alg_handle), BCRYPT_AES_ALGORITHM, None, 0)
        if res:
            raise Exception('fail to BCryptOpenAlgorithmProvider for %s' % BCRYPT_AES_ALGORITHM)
        self._mode = cipher_name.split('-')[-1].upper()
        mode = {
            'CFB': BCRYPT_CHAIN_MODE_CFB, 'CFB8': BCRYPT_CHAIN_MODE_CFB, 'CFB128': BCRYPT_CHAIN_MODE_CFB,
            'GCM': BCRYPT_CHAIN_MODE_GCM
        }.get(self._mode)
        if not mode:
            raise Exception('mode of operation not support for %s' % cipher_name)
        res = bcrypt.BCryptSetProperty(self._alg_handle, BCRYPT_CHAINING_MODE, mode, len(mode), 0)
        if res:
            raise Exception('fail to set BCRYPT_CHAINING_MODE for %s' % cipher_name)

    def update(self, data):
        if hasattr(self, 'encrypt') and hasattr(self, 'decrypt') and hasattr(self, 'op'):
            return {1: self.encrypt(data), 0: self.decrypt(data)}[self.op]
        else:
            raise NotImplementedError('encrypt or decrypt or op is not implemented for %s' % (self.__class__.__name__))

    def clean(self):
        raise NotImplementedError('TODO')
        if hasattr(self, '_key_handle'):
            pass
        pass


class BcryptStreamCrypto(BcryptCryptBase):
    """
    Crypto for stream modes: cfb, ofb, ctr
    """
    def __init__(self, cipher_name, key, iv, op, crypto_path=None):
        cipher_name = cipher_name.lstrip('cng:')
        BcryptCryptBase.__init__(self, cipher_name, crypto_path)

        cb_result = ULONG()
        key_obj_size = DWORD(0)
        res = bcrypt.BCryptGetProperty(self._alg_handle, BCRYPT_OBJECT_LENGTH, byref(key_obj_size), sizeof(key_obj_size), byref(cb_result), 0)
        if res:
            raise Exception('fail to get key object size')
        # iv_obj_size = DWORD(0)
        # res = bcrypt.BCryptGetProperty(self._alg_handle, BCRYPT_BLOCK_LENGTH, byref(iv_obj_size), sizeof(iv_obj_size), byref(cb_result), 0)
        # if res:
        #     raise Exception('fail to get iv object size')

        self._key_obj = create_string_buffer(b'\0' * key_obj_size.value)
        self._iv_obj = create_string_buffer(iv)
        self._key_handle = HANDLE()
        res = bcrypt.BCryptGenerateSymmetricKey(self._alg_handle, byref(self._key_handle), byref(self._key_obj), sizeof(self._key_obj), key, len(key), 0)
        if res:
            raise Exception('fail to set key')

        # set cfb shift size
        if 'CFB' in self._mode.upper():
            shift_size = {'CFB': 16, 'CFB8': 1, 'CFB128': 16}.get(self._mode)
            if not shift_size:
                raise Exception('shift size not support for %s' % self._mode)
            shift_size = DWORD(shift_size)
            res = bcrypt.BCryptSetProperty(self._key_handle, BCRYPT_MESSAGE_BLOCK_LENGTH, cast(byref(shift_size), PUCHAR), sizeof(shift_size), 0)
            if res:
                raise Exception('fail to set BCRYPT_MESSAGE_BLOCK_LENGTH for %s' % cipher_name)

        self.encrypt_once = self.encrypt
        self.decrypt_once = self.decrypt
        self.op = op

    def encrypt(self, data):
        global buf_size, buf
        cb_result = ULONG()
        l = len(data)
        if buf_size < l:
            buf_size = l * 2
            buf = create_string_buffer(buf_size)
        res = bcrypt.BCryptEncrypt(self._key_handle, data, len(data), None, byref(self._iv_obj), sizeof(self._iv_obj), byref(buf), sizeof(buf), byref(cb_result), BCRYPT_BLOCK_PADDING)
        if res:
            raise Exception('fail in BCryptEncrypt')
        return buf.raw[:cb_result.value]

    def decrypt(self, data):
        global buf_size, buf
        cb_result = ULONG()
        l = len(data)
        if buf_size < l:
            buf_size = l * 2
            buf = create_string_buffer(buf_size)
        res = bcrypt.BCryptDecrypt(self._key_handle, data, len(data), None, byref(self._iv_obj), sizeof(self._iv_obj), byref(buf), sizeof(buf), byref(cb_result), BCRYPT_BLOCK_PADDING)
        if res:
            raise Exception('fail in BCryptDecrypt')
        return buf.raw[:cb_result.value]


ciphers = {
    'cng:aes-128-cfb': (16, 16, BcryptStreamCrypto),
    'cng:aes-192-cfb': (24, 16, BcryptStreamCrypto),
    'cng:aes-256-cfb': (32, 16, BcryptStreamCrypto),
    'cng:aes-128-cfb8': (16, 16, BcryptStreamCrypto),
    'cng:aes-192-cfb8': (24, 16, BcryptStreamCrypto),
    'cng:aes-256-cfb8': (32, 16, BcryptStreamCrypto),
    'cng:aes-128-cfb128': (16, 16, BcryptStreamCrypto),
    'cng:aes-192-cfb128': (24, 16, BcryptStreamCrypto),
    'cng:aes-256-cfb128': (32, 16, BcryptStreamCrypto),
}


def run_method(method):

    print(method, ': [stream]', 32)
    key_size, iv_size, kls = ciphers[method]
    cipher = kls(method, b'k' * key_size, b'i' * iv_size, 1)
    decipher = kls(method, b'k' * key_size, b'i' * iv_size, 0)

    util.run_cipher(cipher, decipher)


def test_aes_128_cfb():
    run_method('cng:aes-128-cfb')


def test_aes_256_cfb():
    run_method('cng:aes-256-cfb')


def test_aes_128_cfb8():
    run_method('cng:aes-128-cfb8')
