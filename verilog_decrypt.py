#!/usr/bin/env python3

import argparse
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("key", help="RSA private key in PEM format")
    parser.add_argument("input", help="Verilog file to decrypt")
    parser.add_argument("output", help="Output verilog file")
    args = parser.parse_args()

    f = open(args.key, "r")
    rsa_key = RSA.import_key(f.read())
    f.close()

    fi = open(args.input, "rb")
    fo = open(args.output, "wb")

    is_protected = False
    is_base64 = False
    base64_lines = []
    base64_type = None
    encryption_key = None
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
                        cipher = PKCS1_v1_5.new(rsa_key)
                        encryption_key = cipher.decrypt(data, "")
                    except:
                        pass
                elif base64_type == "data_block":
                    if encryption_key is None:
                        raise Exception("Encryption key wasn't decoded")
                    aes_iv = data[:10] + bytes(6 * [0])
                    aes = AES.new(encryption_key, AES.MODE_CBC, aes_iv)
                    plaintext = aes.decrypt(data)
                    plaintext = plaintext[16:]
                    plaintext = check_and_strip_padding(plaintext)
                    if plaintext.endswith(b"\0"):
                        plaintext = plaintext[:-1]
                    fo.write(plaintext)
            else:
                base64_lines.append(line_str)

        if line.startswith(b"`pragma protect"):
            line = line.decode("utf8").strip()
            param = line.split()[2]

            if param == "begin_protected":
                is_protected = True
            if param == "end_protected":
                is_protected = False
            if param.startswith("data_method="):
                data_method = param.split('"')[1]
                if data_method not in ["aes128-cbc"]:
                    raise Exception("Unsupported data_method: " + data_method)
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
