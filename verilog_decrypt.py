#!/usr/bin/env python3

import argparse
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes


def hash(s):
    m = hashes.Hash(hashes.MD5())
    m.update(b"659a1ac1bbf0491ce65203f31ea112b8")
    m.update(s.encode("utf8"))
    return m.finalize().hex()[-4:]


def check_and_strip_padding(data):
    assert len(data) > 0
    byte = data[-1]
    if byte == 0 or byte > 16 or len(data) < byte:
        raise Exception("Invalid padding")
    padding_len = byte
    for i in range(padding_len):
        if data[-1 - i] != byte:
            raise Exception("Invalid padding")
    return data[:-padding_len]


def extract_encryption_key(blob, params, key_length):
    if len(blob) == key_length:
        return blob

    # Proprietary hacks start here
    if hash(params["encrypt_agent"]) == "fdab":
        if hash(params["version"]) == "ad91":
            return blob[24:24 + key_length]
        if hash(params["version"]) == "e857":
            t = blob[21:]
            return t[key_length // 2:key_length] + t[:key_length // 2][::-1]
        if hash(params["version"]) == "ae96":
            t = blob[26:]
            return t[:key_length // 2][::-1] + t[key_length // 2:key_length]
    print("Unknown key encoding")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("key", help="RSA private key in PEM format")
    parser.add_argument("input", help="Verilog file to decrypt")
    parser.add_argument("output", help="Output verilog file")
    args = parser.parse_args()

    f = open(args.key, "rb")
    rsa_key = load_pem_private_key(f.read(), None)
    f.close()

    fi = open(args.input, "rb")
    fo = open(args.output, "wb")

    is_protected = False
    is_base64 = False
    base64_lines = []
    base64_type = None
    encryption_key = None
    params = {}
    for line in fi:
        if is_base64:
            line_str = line.decode("utf8").strip()
            if line_str.startswith("`pragma protect") or line_str == "":
                s = "".join(base64_lines)
                data = base64.b64decode(s)
                base64_lines = []
                is_base64 = False

                if base64_type == "key_block":
                    try:
                        key_blob = rsa_key.decrypt(data, padding.PKCS1v15())
                        encryption_key = extract_encryption_key(key_blob, params, 16)
                    except:
                        pass
                elif base64_type == "data_block":
                    if encryption_key is None:
                        raise Exception("Encryption key wasn't decoded")
                    aes_iv = data[:10] + bytes(6 * [0])
                    aes = Cipher(algorithms.AES(encryption_key), modes.CBC(aes_iv)).decryptor()
                    plaintext = aes.update(data)
                    plaintext = plaintext[16:]
                    plaintext = check_and_strip_padding(plaintext)
                    if plaintext.endswith(b"\0"):
                        plaintext = plaintext[:-1]
                    fo.write(plaintext)
            else:
                base64_lines.append(line_str)

        if line.startswith(b"`pragma protect"):
            line = line.decode("utf8").strip()
            param = line.split(None, 2)[2]

            if param == "begin_protected":
                is_protected = True
            if param == "end_protected":
                is_protected = False
            if param.startswith("data_method="):
                data_method = param.split('"')[1]
                if data_method not in ["aes128-cbc"]:
                    raise Exception("Unsupported data_method: " + data_method)
            if "=" in param:
                a = param.split("=", 1)
                params[a[0]] = a[1]
            if param in ["key_block", "data_block"]:
                base64_type = param
                is_base64 = True

        else:
            if not is_protected:
                fo.write(line)
    fi.close()
    fo.close()


if __name__ == "__main__":
    main()
