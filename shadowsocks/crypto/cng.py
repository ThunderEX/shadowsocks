from __future__ import absolute_import, division, print_function, \
    with_statement

from ctypes import (
    c_long, byref, create_string_buffer, c_void_p, c_byte,
    c_ulong, c_wchar_p, c_ubyte, POINTER, sizeof, cast, Structure, c_ulonglong
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

from shadowsocks.crypto.aead import AeadCryptoBase
from shadowsocks.crypto import util

ULONGLONG = c_ulonglong
PUCHAR = POINTER(c_ubyte)
PBYTE = POINTER(BYTE)

#
# bcrypt.h
#
# NTSTATUS = LONG
# BCRYPT_HANDLE = HANDLE
# BCRYPT_ALG_HANDLE = HANDLE
# BCRYPT_KEY_HANDLE = HANDLE

# BCrypt structs
BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1


class BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(Structure):
    _fields_ = [
        ('cbSize', ULONG),
        ('dwInfoVersion', ULONG),
        ('pbNonce', PUCHAR),
        ('cbNonce', ULONG),
        ('pbAuthData', PUCHAR),
        ('cbAuthData', ULONG),
        ('pbTag', PUCHAR),
        ('cbTag', ULONG),
        ('pbMacContext', PUCHAR),
        ('cbMacContext', ULONG),
        ('cbAAD', ULONG),
        ('cbData', ULONGLONG),
        ('dwFlags', ULONG),
    ]


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
    # ('BCryptOpenAlgorithmProvider', (POINTER(BCRYPT_ALG_HANDLE), LPCWSTR, LPCWSTR, ULONG), NTSTATUS),
    # ('BCryptGetProperty', (BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, POINTER(ULONG), ULONG), NTSTATUS),
    # ('BCryptSetProperty', (BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG), NTSTATUS),
    # ('BCryptCloseAlgorithmProvider', (BCRYPT_ALG_HANDLE, ULONG), NTSTATUS),
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
tag_buf = None
tag_buf_size = 16


def load_cng(crypto_path=None):
    from ctypes import windll
    global loaded, bcrypt, buf, tag_buf

    bcrypt = windll.bcrypt

    for func_name, argtypes, restype in _func:
        if hasattr(bcrypt, func_name):
            getattr(bcrypt, func_name).argtypes = argtypes
            getattr(bcrypt, func_name).restype = restype

    buf = create_string_buffer(buf_size)
    tag_buf = create_string_buffer(tag_buf_size)
    loaded = True


def xor(buf1, buf2):
    return (int.from_bytes(buf1, 'big') ^ int.from_bytes(buf2, 'big')).to_bytes(max(len(buf1), len(buf2)), 'big')


class CNGCryptBase(object):
    """
    bcrypt crypto base class
    """
    def __init__(self, cipher_name, key, iv, op, crypto_path=None):
        if not loaded:
            load_cng(crypto_path)

        # create a handler
        self._alg_handle = HANDLE()
        res = bcrypt.BCryptOpenAlgorithmProvider(byref(self._alg_handle), BCRYPT_AES_ALGORITHM, None, 0)
        if res:
            self.clean()
            raise Exception('fail to BCryptOpenAlgorithmProvider for %s' % BCRYPT_AES_ALGORITHM)

        # set mode of operation
        self._mode = cipher_name.split('-')[-1].upper()
        mode = {
            'CFB': BCRYPT_CHAIN_MODE_CFB, 'CFB8': BCRYPT_CHAIN_MODE_CFB, 'CFB128': BCRYPT_CHAIN_MODE_CFB,
            'GCM': BCRYPT_CHAIN_MODE_GCM
        }.get(self._mode)
        if not mode:
            raise Exception('mode of operation not support for %s' % cipher_name)
        res = bcrypt.BCryptSetProperty(self._alg_handle, BCRYPT_CHAINING_MODE, mode, len(mode), 0)
        if res:
            self.clean()
            raise Exception('fail to set BCRYPT_CHAINING_MODE for %s' % cipher_name)

        # set cfb shift size
        if 'CFB' in self._mode.upper():
            shift_size = {'CFB': 16, 'CFB8': 1, 'CFB128': 16}.get(self._mode)
            if not shift_size:
                raise Exception('shift size not support for %s' % self._mode)
            shift_size = DWORD(shift_size)
            res = bcrypt.BCryptSetProperty(self._alg_handle, BCRYPT_MESSAGE_BLOCK_LENGTH, cast(byref(shift_size), PUCHAR), sizeof(shift_size), 0)
            if res:
                self.clean()
                raise Exception('fail to set BCRYPT_MESSAGE_BLOCK_LENGTH for %s' % cipher_name)

        # get size of key object
        cb_result = ULONG()
        key_obj_size = DWORD(0)
        res = bcrypt.BCryptGetProperty(self._alg_handle, BCRYPT_OBJECT_LENGTH, byref(key_obj_size), sizeof(key_obj_size), byref(cb_result), 0)
        if res:
            self.clean()
            raise Exception('fail to get key object size')

        # create key handle from algorithm handle
        self._key_obj = create_string_buffer(b'\0' * key_obj_size.value)
        self._key_handle = HANDLE()
        res = bcrypt.BCryptGenerateSymmetricKey(self._alg_handle, byref(self._key_handle), byref(self._key_obj), sizeof(self._key_obj), key, len(key), 0)
        if res:
            self.clean()
            raise Exception('fail to set key')

    def __del__(self):
        self.clean()

    def clean(self):
        if hasattr(self, '_key_handle'):
            bcrypt.BCryptDestroyKey(self._key_handle)
        bcrypt.BCryptCloseAlgorithmProvider(self._alg_handle, 0)


class CNGStreamCrypto(CNGCryptBase):
    """
    Crypto for stream modes: cfb, ofb, ctr
    """
    def __init__(self, cipher_name, key, iv, op, crypto_path=None):
        if cipher_name[:len('cng:')] == 'cng:':
            cipher_name = cipher_name[len('cng:'):]
        CNGCryptBase.__init__(self, cipher_name, key, iv, op, crypto_path)
        self.encrypt_once = self.encrypt
        self.decrypt_once = self.decrypt

        # get size of iv object
        # cb_result = ULONG()
        # iv_obj_size = DWORD(0)
        # res = bcrypt.BCryptGetProperty(self._alg_handle, BCRYPT_BLOCK_LENGTH, byref(iv_obj_size), sizeof(iv_obj_size), byref(cb_result), 0)
        # if res:
        #     self.clean()
        #     raise Exception('fail to get iv object size')
        # block_size = iv_obj_size.value

        self._iv_obj = create_string_buffer(iv, len(iv))

        # byte counter, not block counter
        self._counter = 0

    def encrypt(self, data):
        global buf_size, buf
        l = len(data)
        block_size = len(self._iv_obj)
        if self._counter:
            remain_len = self._counter + l - block_size
            if remain_len > 0:
                result = b'\0' * self._counter + data[:block_size - self._counter]
            else:
                result = b'\0' * self._counter + data + b'\0' * -remain_len
            self._iv_obj.raw = xor(self._iv_obj.raw, result)
            result = self._iv_obj.raw[self._counter:self._counter + l]
        else:
            remain_len = l
            result = b''
        if remain_len > 0:
            pad_len = - remain_len % block_size
            remain_data = data[-remain_len:] + b'\0' * pad_len
            cb_result = ULONG()
            if buf_size < remain_len + pad_len:
                buf_size = (remain_len + pad_len) * 2
                buf = create_string_buffer(buf_size)
            res = bcrypt.BCryptEncrypt(self._key_handle, remain_data, remain_len + pad_len, None, byref(self._iv_obj), block_size, byref(buf), buf_size, byref(cb_result), 0)
            if res:
                self.clean()
                raise Exception('fail in BCryptEncrypt')
            result += buf.raw[:remain_len]
        self._counter = (self._counter + l) % block_size
        return result

    def decrypt(self, data):
        global buf_size, buf
        l = len(data)
        block_size = len(self._iv_obj)
        if self._counter % block_size:
            last_plain = buf.raw[self._counter // block_size * block_size:self._counter // block_size * block_size + block_size]
            remain_len = self._counter + l - block_size
            if remain_len > 0:
                self._iv_obj.raw = self._iv_obj.raw[:self._counter] + data[:block_size - self._counter]
            else:
                self._iv_obj.raw = self._iv_obj.raw[:self._counter] + data + b'\0' * -remain_len
            result = xor(self._iv_obj.raw, last_plain)[self._counter:]
        else:
            remain_len = l
            result = b''
        if remain_len > 0:
            pad_len = - remain_len % block_size
            remain_data = data[-remain_len:] + b'\0' * pad_len
            cb_result = ULONG()
            if buf_size < remain_len + pad_len:
                buf_size = (remain_len + pad_len) * 2
                buf = create_string_buffer(buf_size)
            res = bcrypt.BCryptDecrypt(self._key_handle, remain_data, remain_len + pad_len, None, byref(self._iv_obj), block_size, byref(buf), buf_size, byref(cb_result), 0)
            if res:
                self.clean()
                raise Exception('fail in BCryptDecrypt')
            result += buf.raw[:remain_len]
        self._counter = remain_len
        return result


class CNGAeadCrypto(CNGCryptBase, AeadCryptoBase):
    """
    Implement CNG Aead mode: gcm
    """
    def __init__(self, cipher_name, key, iv, op, crypto_path=None):
        global tag_buf_size, tag_buf

        if cipher_name[:len('cng:')] == 'cng:':
            cipher_name = cipher_name[len('cng:'):]
        AeadCryptoBase.__init__(self, cipher_name, key, iv, op, crypto_path)
        CNGCryptBase.__init__(self, cipher_name, self._skey, iv, op, crypto_path)

        # reserve buffer for tag
        if tag_buf_size < self._tlen:
            tag_buf_size = self._tlen * 2
            tag_buf = create_string_buffer(tag_buf_size)

        # in place of macro BCRYPT_INIT_AUTH_MODE_INFO
        self._auth_cipher_mode_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(
            sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO),
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        )

        # further setup _auth_cipher_mode_info
        self._auth_cipher_mode_info.pbNonce = cast(byref(self._nonce), PUCHAR)
        self._auth_cipher_mode_info.cbNonce = self._nlen
        self._auth_cipher_mode_info.cbTag = self._tlen

        self.encrypt_once = self.aead_encrypt
        self.decrypt_once = self.aead_decrypt

    def aead_encrypt(self, data):
        """
        Encrypt data with authenticate tag

        :param data: plain text
        :return: cipher text with tag
        """
        global buf_size, buf
        cb_result = ULONG()
        plen = len(data)
        if buf_size < plen:
            buf_size = plen * 2
            buf = create_string_buffer(buf_size)
        self._auth_cipher_mode_info.pbTag = cast(byref(tag_buf), PUCHAR)
        res = bcrypt.BCryptEncrypt(self._key_handle, data, plen, byref(self._auth_cipher_mode_info), None, 0, byref(buf), buf_size, byref(cb_result), 0)
        if res:
            self.clean()
            raise Exception('fail in BCryptEncrypt')
        return buf.raw[:cb_result.value] + tag_buf[:self._tlen]

    def aead_decrypt(self, data):
        """
        Decrypt data and authenticate tag

        :param data: cipher text with tag
        :return: plain text
        """
        global buf_size, buf
        cb_result = ULONG()
        plen = len(data) - self._tlen
        if buf_size < plen:
            buf_size = plen * 2
            buf = create_string_buffer(buf_size)
        tag = create_string_buffer(data[-self._tlen:])
        self._auth_cipher_mode_info.pbTag = cast(byref(tag), PUCHAR)
        res = bcrypt.BCryptDecrypt(self._key_handle, data, plen, byref(self._auth_cipher_mode_info), None, 0, byref(buf), buf_size, byref(cb_result), 0)
        if res:
            self.clean()
            raise Exception('fail in BCryptDecrypt')
        return buf.raw[:cb_result.value]


ciphers = {
    'cng:aes-128-cfb': (16, 16, CNGStreamCrypto),
    'cng:aes-192-cfb': (24, 16, CNGStreamCrypto),
    'cng:aes-256-cfb': (32, 16, CNGStreamCrypto),
    'cng:aes-128-cfb8': (16, 16, CNGStreamCrypto),
    'cng:aes-192-cfb8': (24, 16, CNGStreamCrypto),
    'cng:aes-256-cfb8': (32, 16, CNGStreamCrypto),
    'cng:aes-128-cfb128': (16, 16, CNGStreamCrypto),
    'cng:aes-192-cfb128': (24, 16, CNGStreamCrypto),
    'cng:aes-256-cfb128': (32, 16, CNGStreamCrypto),
    'cng:aes-128-gcm': (16, 16, CNGAeadCrypto),
    'cng:aes-192-gcm': (24, 24, CNGAeadCrypto),
    'cng:aes-256-gcm': (32, 32, CNGAeadCrypto),
}


def run_method(method):

    print(method, ': [stream]', 32)
    key_size, iv_size, kls = ciphers.get(method, ciphers.get('cng:' + method))
    cipher = kls(method, b'k' * key_size, b'i' * iv_size, 1)
    decipher = kls(method, b'k' * key_size, b'i' * iv_size, 0)

    util.run_cipher(cipher, decipher)
