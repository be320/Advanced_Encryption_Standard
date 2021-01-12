import binascii
import re
from tables import *

class AES(object):

    def __init__(self, iv=None):
        self.iv = iv
        self.Nb = 0
        self.Nk = 0
        self.Nr = 0

    @staticmethod
    def pad(data, block=16):
        if len(data) is block: return data
        pads = block - (len(data) % block)
        return data + binascii.unhexlify(('%02x' % int(pads)).encode()) + b'\x00' * (pads - 1)

    @staticmethod
    def unpad(data):
        p = None
        for x in data[::-1]:
            if x is 0:
                continue
            elif x is not 0:
                p = x; break
        data = data[::-1]
        data = data[p:]
        return data[::-1]

    @staticmethod
    def unblock(data, size=16):
        return [data[x:x + size] for x in range(0, len(data), size)]

    @staticmethod
    def RotWord(word):
        return int(word[2:] + word[0:2], 16)

    @staticmethod
    def StateMatrix(state):
        new_state = []
        split = re.findall('.' * 2, state)
        for x in range(4):
            new_state.append(split[0:4][x]); new_state.append(split[4:8][x])
            new_state.append(split[8:12][x]); new_state.append(split[12:16][x])
        return new_state

    @staticmethod
    def RevertStateMatrix(state):
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        return ''.join(''.join([columns[0][x], columns[1][x], columns[2][x], columns[3][x]]) for x in range(4))

    @staticmethod
    def galois(a, b):
        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    @staticmethod
    def AddRoundKey(state, key):
        return ['%02x' % (int(state[x], 16) ^ int(key[x], 16)) for x in range(16)]

    def ShiftRows(self, state, isInv):
        offset = 0
        if isInv: state = re.findall('.' * 2, self.RevertStateMatrix(state))
        for x in range(0, 16, 4):
            state[x:x + 4] = state[x:x + 4][offset:] + state[x:x + 4][:offset]
            if not isInv:
                offset += 1
            elif isInv:
                offset -= 1
        if isInv: return self.StateMatrix(''.join(state))
        return state

    def SubWord(self, byte):
        return ((sbox[(byte >> 24 & 0xff)] << 24) + (sbox[(byte >> 16 & 0xff)] << 16) +
                (sbox[(byte >> 8 & 0xff)] << 8) + sbox[byte & 0xff])

    def SubBytes(self, state, isInv):
        if not isInv: return ['%02x' % sbox[int(state[x], 16)] for x in range(16)]
        elif isInv: return ['%02x' % rsbox[int(state[x], 16)] for x in range(16)]

    def MixColumns(self, state, isInv):
        if isInv: fixed = [14, 9, 13, 11]; state = self.StateMatrix(''.join(state))
        else: fixed = [2, 1, 1, 3]
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        row = [0, 3, 2, 1]
        col = 0
        output = []
        for _ in range(4):
            for _ in range(4):
                output.append('%02x' % (
                    self.galois(int(columns[row[0]][col], 16), fixed[0]) ^
                    self.galois(int(columns[row[1]][col], 16), fixed[1]) ^
                    self.galois(int(columns[row[2]][col], 16), fixed[2]) ^
                    self.galois(int(columns[row[3]][col], 16), fixed[3])))
                row = [row[-1]] + row[:-1]
            col += 1
        return output

    def Cipher(self, expandedKey, data):
        state = self.AddRoundKey(self.StateMatrix(data), expandedKey[0])
        for r in range(self.Nr - 1):
            state = self.SubBytes(state, False)
            state = self.ShiftRows(state, False)
            state = self.StateMatrix(''.join(self.MixColumns(state, False)))
            state = self.AddRoundKey(state, expandedKey[r + 1])

        state = self.SubBytes(state, False)
        state = self.ShiftRows(state, False)
        state = self.AddRoundKey(state, expandedKey[self.Nr])
        return self.RevertStateMatrix(state)

    def InvCipher(self, expandedKey, data):
        state = self.AddRoundKey(re.findall('.' * 2, data), expandedKey[self.Nr])
        for r in range(self.Nr - 1):
            state = self.ShiftRows(state, True)
            state = self.SubBytes(state, True)
            state = self.AddRoundKey(state, expandedKey[-(r + 2)])
            state = self.MixColumns(state, True)

        state = self.ShiftRows(state, True)
        state = self.SubBytes(state, True)
        state = self.AddRoundKey(state, expandedKey[0])
        return ''.join(state)

    def ExpandKey(self, key):
        w = ['%08x' % int(x, 16) for x in re.findall('.' * 8, key)]

        i = self.Nk
        while i < self.Nb * (self.Nr + 1):
            temp = w[i - 1]
            if i % self.Nk is 0:
                temp = '%08x' % (self.SubWord(self.RotWord(temp)) ^ (rcon[i // self.Nk] << 24))
            elif self.Nk > 6 and i % self.Nk is 4:
                temp = '%08x' % self.SubWord(int(temp, 16))
            w.append('%08x' % (int(w[i - self.Nk], 16) ^ int(temp, 16)))
            i += 1

        return [self.StateMatrix(''.join(w[x:x + 4])) for x in range(0, len(w), self.Nk)]

    def key_handler(self, key, isInv):
        self.Nb = 4; self.Nk = 4; self.Nr = 10
        if not isInv: return self.ExpandKey(key)
        if isInv: return [re.findall('.' * 2, self.RevertStateMatrix(x)) for x in self.ExpandKey(key)]

    def encryption(self, data, key):
        expanded_key = self.key_handler(key, False)
        return self.ecb(data, expanded_key, False)

    def decryption(self, data, key):
        expanded_key = self.key_handler(key, True)
        return self.ecb(data, expanded_key, True)

    def ecb(self, data, expanded_key, isInv):
        if not isInv: return self.Cipher(expanded_key, data)
        elif isInv: return self.InvCipher(expanded_key, data)
       