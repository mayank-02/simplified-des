class SimplifiedDES(object):
    """Simplified DES is a simplified version of DES algorithm"""

    # Key size in bits
    key_size = 10

    """ Tables for initial and final permutations (b1, b2, b3, ... b8) """
    # Initial permutation
    IP_table = (2, 6, 3, 1, 4, 8, 5, 7)

    # Final permutation (Inverse of intial)
    FP_table = (4, 1, 3, 5, 7, 2, 8, 6)

    """ Tables for subkey generation (k1, k2, k3, ... k10) """
    P10_table = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)

    P8_table = (6, 3, 7, 4, 8, 5, 10, 9)

    """ Tables for the fk function """
    # Expansion permutation
    EP_table = (4, 1, 2, 3, 2, 3, 4, 1)

    # Substitution Box 0
    S0_table = (1, 0, 3, 2, 3, 2, 1, 0, 0, 2, 1, 3, 3, 1, 3, 2)

    # Substitution Box 1
    S1_table = (0, 1, 2, 3, 2, 0, 1, 3, 3, 0, 1, 0, 2, 1, 0, 3)

    # Permutation Table
    P4_table = (2, 4, 3, 1)

    def __init__(self, key):
        self.key = key
        self.subKey1, self.subKey2 = self.generate_key(self.key)

    def _perm(self, inputByte, permTable):
        """Permute input byte according to permutation table

        :param inputByte: byte to permute
        :param permTable: table to use for permutation
        :returns: permuted byte
        """
        outputByte = 0
        for index, elem in enumerate(permTable):
            if index >= elem:
                outputByte |= (inputByte & (128 >> (elem - 1))) >> (index - (elem - 1))
            else:
                outputByte |= (inputByte & (128 >> (elem - 1))) << ((elem - 1) - index)
        return outputByte

    def ip(self, inputByte):
        """Perform the initial permutation on data"""
        return self._perm(inputByte, self.IP_table)

    def fp(self, inputByte):
        """Perform the final permutation on data """
        return self._perm(inputByte, self.FP_table)

    def swap_nibbles(self, inputByte):
        """Swap the two nibbles of the byte """
        return (inputByte << 4 | inputByte >> 4) & 0xFF

    def left_shift(self, keyBitList):
        """Perform a circular left shift on the first and second set of five bits

        before = | 1| 2| 3| 4| 5| 6| 7| 8| 9|10|
        after  = | 2| 3| 4| 5| 1| 7| 8| 9|10| 6|

        :param keyBitList: list of bits
        :returns: circularly left shifted list of bits
        """
        shiftedKey = [None] * self.key_size
        shiftedKey[0:9] = keyBitList[1:10]
        shiftedKey[4] = keyBitList[0]
        shiftedKey[9] = keyBitList[5]

        return shiftedKey

    def generate_key(self, key):
        """Generate the two required subkeys

        K1 = P8(LS1(P10(key)))

        K2 = P8(LS2(LS1(P10(key))))

        :param key: key to be used for encryption and/or decryption
        :returns: tuple containing first subkey and second subkey
        """
        # Convert input key (integer) into a list of binary digits
        keyList = [(key & 1 << i) >> i for i in reversed(range(self.key_size))]

        # Initialise permuted key list to None
        permKeyList = [None] * self.key_size

        # To fill output of P10 permutation table and input
        for index, elem in enumerate(self.P10_table):

            # P10(key)
            permKeyList[index] = keyList[elem - 1]

        # LS1(P10(key))
        shiftedOnceKey = self.left_shift(permKeyList)

        # LS2(LS1(P10(key)))
        shiftedTwiceKey = self.left_shift(self.left_shift(shiftedOnceKey))

        subKey1 = subKey2 = 0
        for index, elem in enumerate(self.P8_table):

            # Apply P8() on first subkey
            subKey1 += (128 >> index) * shiftedOnceKey[elem - 1]

            # Apply P8() on second subkey
            subKey2 += (128 >> index) * shiftedTwiceKey[elem - 1]

        return (subKey1, subKey2)

    def F(self, sKey, rightNibble):
        """Round function
        1. Expansion Permutation Box
        2. XOR
        3. Substitution Boxes
        4. Permutation

        :param sKey: subkey to be used to for this round
        :param rightNibble: right nibble of the 8 bit input to this round
        :returns: 4 bit output
        """
        # Right nibble is permuted using EP and XOR'd with first key
        aux = sKey ^ self._perm(self.swap_nibbles(rightNibble), self.EP_table)

        # Find indices into the S-box S0
        index0 = (
            ((aux & 0x80) >> 4)
            + ((aux & 0x40) >> 5)
            + ((aux & 0x20) >> 5)
            + ((aux & 0x10) >> 2)
        )

        # Find indices into the S-box S1
        index1 = (
            ((aux & 0x08) >> 0)
            + ((aux & 0x04) >> 1)
            + ((aux & 0x02) >> 1)
            + ((aux & 0x01) << 2)
        )

        # S0(b1b2b3b4) = the [ b1b4 , b2b3 ] cell from the "S-box" S0
        # and similarly for S1
        sboxOutputs = self.swap_nibbles(
            (self.S0_table[index0] << 2) + self.S1_table[index1]
        )

        # Apply permutation
        return self._perm(sboxOutputs, self.P4_table)

    def fk(self, subKey, inputData):
        """Apply Feistel function on data with given subkey

        :param subKey: subkey to be used to for this round
        :param inputData: 8 bit input for this round
        :returns: 8 bit output
        """
        # Divide the permuted bits into 2 halves
        leftNibble = inputData & 0xF0
        rightNibble = inputData & 0x0F

        # Apply F
        FOutput = self.F(subKey, rightNibble)

        # Return left nibble and right nibble
        return (leftNibble ^ FOutput) | rightNibble

    def encrypt(self, plaintext):
        """Encrypt plaintext with given key

        ciphertext = IP^-1( fK2( SW( fK1( IP( plaintext ) ) ) ) )

        Example::

            ciphertext = SimplifiedDES(3).encrypt(0b10101111)

        :param plaintext: 8 bit plaintext
        :returns: 8 bit ciphertext
        """
        permuted_text = self.ip(plaintext)

        first_round_output = self.fk(self.subKey1, permuted_text)

        second_round_output = self.fk(
            self.subKey2, self.swap_nibbles(first_round_output)
        )

        return self.fp(second_round_output)

    def decrypt(self, ciphertext):
        """Decrypt ciphertext with given key

        plaintext = IP^-1( fK1( SW( fK2( IP( ciphertext ) ) ) ) )

        Example::

            plaintext = SimplifiedDES(3).decrypt(0b10101111)

        :param ciphertext: 8 bit ciphertext
        :returns: 8 bit plaintext
        """
        permuted_text = self.ip(ciphertext)

        first_round_output = self.fk(self.subKey2, permuted_text)

        second_round_output = self.fk(
            self.subKey1, self.swap_nibbles(first_round_output)
        )

        return self.fp(second_round_output)
