import configparser
import os
import time

def bytes_to_binary(bytes_array: list[int]) -> str:
    binary_string = ''
    for byte in bytes_array:
        st = bin(byte)[2:]
        while len(st) < 8:
            st = '0' + st
        binary_string += st
    return binary_string


def text_to_binary_utf8(text):
    binary_representation = ''.join(format(byte, '08b') for byte in text.encode('utf-8'))
    return binary_representation


def binary_to_bytes(binary: str) -> str:
    byte_strings = [binary[i:i + 4] for i in range(0, len(binary), 4)]
    byte_array = [hex(int(byte, 2))[2:] for byte in byte_strings]
    return ''.join(byte_array)


class SHA3():
    def __init__(self):
        self.path_configuration = 'configuration/config.ini'
        self.config = configparser.ConfigParser()
        self.config.read(self.path_configuration)
        self.d = int(self.config.get('Parameters', 'd'))  # The length of the digest of a hash function
        self.c = int(self.config.get('Parameters', 'c'))  # The capacity of a sponge function
        self.l = int(self.config.get('Parameters', 'l'))
        self.mode = int(self.config.get('Parameters', 'mode'))
        self.w = 2 ** self.l
        self.A = [[[0 for _ in range(self.w)] for _ in range(5)] for _ in range(5)]
        self.b = 25 * 2 ** self.l
        self.r = self.b - self.c  # the rate of sponge function
        self.rounds = 12 + 2 * self.l

    def _1Dto3D(self, A):
        A_out = [[[0 for _ in range(self.w)] for _ in range(5)] for _ in range(5)]
        for i in range(5):
            for j in range(5):
                for k in range(self.w):
                    A_out[i][j][k] = int(A[self.w * (5 * j + i) + k])
        return A_out

    def _3Dto1D(self, A):
        A_out = ['0' for _ in range(self.b)]
        for i in range(5):
            for j in range(5):
                for k in range(self.w):
                    A_out[self.w * (5 * j + i) + k] = str(A[i][j][k])
        return A_out

    def theta(self):
        C = [[0 for _ in range(self.w)] for _ in range(5)]
        D = [[0 for _ in range(self.w)] for _ in range(5)]
        for x in range(5):
            for z in range(self.w):
                C[x][z] = self.A[x][0][z] ^ self.A[x][1][z] ^ self.A[x][2][z] ^ self.A[x][3][z] ^ self.A[x][4][z]
        for x in range(5):
            for z in range(self.w):
                D[x][z] = C[(x - 1) % 5][z] ^ C[(x + 1) % 5][(z - 1) % self.w]
        for x in range(5):
            for y in range(5):
                for z in range(self.w):
                    self.A[x][y][z] = self.A[x][y][z] ^ D[x][z]

    def rho(self):
        x, y = 1, 0
        A_copy = [[[0 for _ in range(self.w)] for _ in range(5)] for _ in range(5)]
        for z in range(self.w):
            A_copy[0][0][z] = self.A[0][0][z]
        for t in range(24):
            for z in range(self.w):
                A_copy[x][y][z] = self.A[x][y][(z - (t - 1) * (t + 2) // 2) % self.w]
            x, y = y, (2 * x + 3 * y) % 5
        self.A = A_copy

    def pi(self):
        A_copy = [[[0 for _ in range(self.w)] for _ in range(5)] for _ in range(5)]
        for x in range(5):
            for y in range(5):
                for z in range(self.w):
                    A_copy[x][y][z] = self.A[(x + 3 * y) % 5][x][z]
        self.A = A_copy

    def chi(self):
        A_copy = [[[0 for _ in range(self.w)] for _ in range(5)] for _ in range(5)]
        for x in range(5):
            for y in range(5):
                for z in range(self.w):
                    A_copy[x][y][z] = self.A[x][y][z] ^ ((self.A[(x + 1) % 5][y][z] ^ 1) * self.A[(x + 2) % 5][y][z])
        self.A = A_copy

    def rc(self, t: int):
        if t % 255 == 0:
            return 1
        R = [1, 0, 0, 0, 0, 0, 0, 0]
        for i in range(1, t % 255 + 1):
            R.insert(0, 0)
            R[0] = R[0] ^ R[8]
            R[4] = R[4] ^ R[8]
            R[5] = R[5] ^ R[8]
            R[6] = R[6] ^ R[8]
            R = R[0:8]
        return R[0]

    def iota(self, i_r):
        A_copy = self.A.copy()
        RC = [0] * self.w
        for j in range(self.l + 1):
            RC[2 ** j - 1] = self.rc(j + 7 * i_r)
        for z in range(self.w):
            A_copy[0][0][z] = A_copy[0][0][z] ^ RC[z]
        self.A = A_copy

    def rnd(self, ir):
        self.theta()
        self.rho()
        self.pi()
        self.chi()
        self.iota(ir)

    def Keccak_f(self, b: str):
        self.A = self._1Dto3D(b)
        for ir in range(0, 12 + 2 * self.l):
            self.rnd(ir)
        new_b = self._3Dto1D(self.A)
        return new_b

    def pad(self, message):
        return message + '1' + '0' * ((-1 * len(message) - 2) % self.r) + '1'

    def split(self, string):
        return [string[i:i + self.r] for i in range(0, len(string), self.r)]

    def sponge(self, N):
        P = self.pad(N)
        n = len(P) // self.r
        P = self.split(P)
        S = ['0'] * self.b
        for i in range(n):
            P_curr = P[i]
            for j in range(self.r):
                S[j] = str(int(S[j]) ^ int(P_curr[j]))
            S = self.Keccak_f(S)
        Z = S[0:self.r]
        while self.d > len(Z):
            S = self.Keccak_f(S)
            Z.extend(S[0:self.r])
        return ''.join(Z[0:self.d])

    def sha_3(self, M):
        M += '01'
        return self.sponge(M)


def main():
    sha = SHA3()
    path = str(input('Enter the filename in the current directory: '))
    if sha.mode == 1:
        with open(path, 'rb') as file:
            content = file.read()
        binary = bytes_to_binary(list(content))
    elif sha.mode == 2:
        with open(path, 'r') as file:
            content = file.read()
        binary = text_to_binary_utf8(content)
    binary = '1001000'
    digest = sha.sha_3(binary)
    digest_hex = binary_to_bytes(digest)
    filename, _ = os.path.splitext(path)
    with open(filename + '_digest' + '.txt', 'w') as file:
        file.write(digest_hex)


if __name__ == "__main__":
    main()
