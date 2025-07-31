#!/usr/bin/env python3

import sys
import os
import struct
from binascii import hexlify


def stringify_hex(hex_bytes: bytes):
    return hexlify(hex_bytes).decode("utf-8")

def safe_unpack(fmt, data, index):
    size = struct.calcsize(fmt)
    if index + size > len(data):
        raise ValueError("Insufficient data length for unpacking.")
    return struct.unpack(fmt, data[index:index+size])[0], index + size


def process_1x_database(data, database_name, max_inline_size=1024):
    index = 8
    algorithm = -1

    enc_flag = struct.unpack("<L", data[index:index+4])[0]
    index += 4
    if (enc_flag & 2 == 2):
        # AES
        algorithm = 0
    elif (enc_flag & 8):
        # Twofish
        algorithm = 1
    else:
        print("Unsupported file encryption!")
        return

    key_file_size = struct.unpack("<L", data[index:index+4])[0]
    index += 4
    keyfile = hexlify(data[index:index+key_file_size])
    index += key_file_size

    version = hexlify(data[index:index+4])
    index += 4

    final_random_seed = stringify_hex(data[index:index+16])
    index += 16

    iv_params = stringify_hex(data[index:index+16])
    index += 16

    num_groups = struct.unpack("<L", data[index:index+4])[0]
    index += 4
    num_entries = struct.unpack("<L", data[index:index+4])[0]
    index += 4

    contents_hash = stringify_hex(data[index:index+32])
    index += 32

    transform_random_seed = stringify_hex(data[index:index+32])
    index += 32

    key_transform_rounds = struct.unpack("<L", data[index:index+4])[0]

    filesize = len(data)
    datasize = filesize - 124

    if ((filesize + datasize) < max_inline_size):
        data_buffer = hexlify(data[124:])
        end = "*1*%ld*%s" % (datasize, stringify_hex(data_buffer))
    else:
        end = "0*%s" % database_name

    print("1x database properties:")
    print("Keyfile: %s\nVersion: %s\nNumber of groups: %s\nNumber of entries: %s\n" % (keyfile, version, num_groups, num_entries))

    return "%s<SHOULD_BE_REMOVED_INCLUDING_COLON>:$keepass$*1*%s*%s*%s*%s*%s*%s*%s" % (
        database_name, key_transform_rounds, algorithm,
        final_random_seed, transform_random_seed, iv_params, contents_hash, end
    )


def process_2x_database(data, database_name):
    index = 12
    end_reached = False
    master_seed = b''
    transform_seed = b''
    transform_rounds = 0
    iv_parameters = b''
    expected_start_bytes = b''

    FIELD_IDs = {
        'END': 0,
        'MASTER_SEED': 4,
        'TRANSFORM_SEED': 5,
        'TRANSFORM_ROUNDS': 6,
        'IV_PARAMETERS': 7,
        'EXPECTED_START_BYTES': 9
    }

    while not end_reached:

        btFieldID, index = safe_unpack("B", data, index)

        # btFieldID = struct.unpack("B", data[index:index+1])[0]
        # index += 1

        uSize, index = safe_unpack("H", data, index)

        # uSize = struct.unpack("H", data[index:index+2])[0]
        # index += 2

        if btFieldID == FIELD_IDs["END"]:
            end_reached = True

        elif btFieldID == FIELD_IDs["MASTER_SEED"]:
            master_seed = stringify_hex(data[index:index+uSize])
            index += uSize

        elif btFieldID == FIELD_IDs["TRANSFORM_SEED"]:
            transform_seed = stringify_hex(data[index:index+uSize])
            index += uSize

        elif btFieldID == FIELD_IDs["TRANSFORM_ROUNDS"]:
            # fFor transform_rounds, uSize should always be 8.
            if uSize != 8:
                raise ValueError("Invalid uSize for field 'transform_rounds'.")
            transform_rounds, index = safe_unpack("Q", data, index)

        elif btFieldID == FIELD_IDs["IV_PARAMETERS"]:
            iv_parameters = stringify_hex(data[index:index+uSize])
            index += uSize

        elif btFieldID == FIELD_IDs["EXPECTED_START_BYTES"]:
            expected_start_bytes = stringify_hex(data[index:index+uSize])
            index += uSize

        else:
            # Skip unknown field ids.
            sys.stderr.write(f"Warning: Unknown field ID encountered: {btFieldID}."
                             "This may indicate a newer KeePass file format. \n")
            index += uSize

    dataStartOffset = index
    firstEncryptedBytes = stringify_hex(data[index:index+32])

    return "%s<SHOULD_BE_REMOVED_INCLUDING_COLON>:$keepass$*2*%s*%s*%s*%s*%s*%s*%s" % (
        database_name, transform_rounds, dataStartOffset, master_seed,
        transform_seed, iv_parameters, expected_start_bytes,
        firstEncryptedBytes
    )


processing_mapping = {
    b'03d9a29a67fb4bb5': process_2x_database, # "2.X"
    b'03d9a29a66fb4bb5': process_2x_database, # "2.X pre release"
    b'03d9a29a65fb4bb5': process_1x_database  # "1.X"
}


def process_database(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    base = os.path.basename(filename)
    database_name = os.path.splitext(base)[0]

    file_signature = hexlify(data[0:8])

    try:
        print(processing_mapping[file_signature](data, database_name))
    except KeyError:
        print("ERROR: KeePass signature unrecognized")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <kdb[x] file[s]>\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_database(sys.argv[i])
