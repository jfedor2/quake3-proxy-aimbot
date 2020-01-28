import struct

import huffman
import defs


class Buffer:

    def __init__(self, source=None, trace=None):
        if source is not None:
            self.data = bytearray(source)
        else:
            self.data = bytearray()
        self.trace = trace
        self.offset = 0

    def write_raw_bits(self, value, nbits):
        for i in range(nbits):
            if self.offset % 8 == 0:
                self.data += b'\x00'
            self.data[self.offset // 8] |= ((value >> i) & 1) << (self.offset % 8)
            self.offset += 1

    def read_raw_bits(self, nbits, passthru=None):
        value = 0
        for i in range(nbits):
            value |= ((self.data[self.offset // 8] >> (self.offset % 8)) & 1) << i
            self.offset += 1
        if passthru:
            passthru.write_raw_bits(value, nbits)
        return value

    def write_bit(self, value):
        self.write_raw_bits(value, 1)

    def read_bit(self, description=None, passthru=None):
        value = self.read_raw_bits(1)
        if passthru:
            passthru.write_bit(value)
        if self.trace:
            self.trace.add(description, value)
        return value

    def read_bits(self, nbits, description=None, passthru=None):
        if nbits < 0:
            nbits = -nbits
            signed = True
        else:
            signed = False
        uneven_bits = nbits & 7
        value = self.read_raw_bits(uneven_bits)
        for i in range((nbits - uneven_bits) // 8):
            decoded = huffman.fixed_decoder.decode(self, 1)
            value += (int.from_bytes(decoded, 'little') * 2**(uneven_bits + i * 8))
        if signed and value & (1 << (nbits - 1)):
            value -= 1 << nbits
        if passthru:
            passthru.write_bits(value, nbits)
        if self.trace:
            self.trace.add(description, value)
        return value

    def write_bits(self, value, nbits):
        uneven_bits = nbits & 7
        self.write_raw_bits(value, uneven_bits)
        value = value >> uneven_bits
        for _ in range((nbits - uneven_bits) // 8):
            huffman.fixed_decoder.encode(value & 0xff, self)
            value = value >> 8

    def read_string(self, description=None, passthru=None):
        string = b''
        while True:
            char = self.read_bits(8)
            string += bytes([char])
            if char == 0:
                break
        if passthru:
            passthru.write_string(string)
        if self.trace:
            self.trace.add(description,
                           '"' + string.decode('ascii', errors='backslashreplace') + '"')
        return string

    def write_string(self, string):
        for char in string:
            self.write_bits(char, 8)

    def read_delta_key(self, bits, old, key, description=None):
        if self.read_bit("{}_changed".format(description)):
            value = self.read_bits(bits) ^ (key & 2**bits - 1)
            if self.trace:
                self.trace.add(description, value)
            return value
        return old

    def write_delta_key(self, value, old, bits, key):
        if old is not None and value & (2**bits - 1) == old & (2**bits - 1):
            self.write_bit(0)
        else:
            self.write_bit(1)
            self.write_bits(value ^ (key & (2**bits - 1)), bits)

    def read_float(self, description=None):
        value = struct.unpack('<f', huffman.fixed_decoder.decode(self, 4))[0]
        if self.trace:
            self.trace.add(description, value)
        return value

    def read_int_float(self, description=None):
        value = self.read_bits(defs.FLOAT_INT_BITS) - defs.FLOAT_INT_BIAS
        if self.trace:
            self.trace.add(description, value)
        return value

    def xor(self, start, key, last_command):
        index = 0
        for i in range(start, len(self.data)):
            if index >= len(last_command) or last_command[index] == 0:
                index = 0
            if last_command[index] > 127 or last_command[index] == ord('%'):
                key ^= ord('.') << (i & 1)
            else:
                key ^= last_command[index] << (i & 1)
            index += 1
            self.data[i] ^= key & 0xff
