import binascii

s_box = {
    '0000': '1100', '0001': '0101',
    '0010': '0110', '0011': '1011',
    '0100': '1001', '0101': '0000',
    '0110': '1010', '0111': '1101',
    '1000': '0011', '1001': '1110',
    '1010': '1111', '1011': '1000',
    '1100': '0100', '1101': '0111',
    '1110': '0001', '1111': '0010',
}

p_box = [
    '0', '16', '32', '48', '1', '17', '33', '49',
    '2', '18', '34', '50', '3', '19', '35', '51',
    '4', '20', '36', '52', '5', '21', '37', '53',
    '6', '22', '38', '54', '7', '23', '39', '55',
    '8', '24', '40', '56', '9', '25', '41', '57',
    '10', '26', '42', '58', '11', '27', '43', '59',
    '12', '28', '44', '60', '13', '29', '45', '61',
    '14', '30', '46', '62', '15', '31', '47', '63',
]


def convert_to_bits(a):
    return ' '.join(format(ord(x), 'b') for x in a)


K = ''
blocks = []
round_keys = []
round_counter = 1


ind = 0
for a in range(80):
    if ind == 19:
        #bit = 1
        bit = 0
    else:
        # bit = random.randint(0, 1)
        bit = 0
    K = K + str(bit)
    ind += 1


def offset_bits(key):
    key = key[61:80] + key[0:61]
    return key


def xor_operation(a, b):
    b_bin = '{0:05b}'.format(b)
    res = ''
    a = list(a)
    b = list(str(b_bin))
    for x, y in zip(a, b):
        r = int(x) ^ int(y)
        res = res + str(r)
    return res


def generate_round_keys():
    global round_keys, round_counter, K
    key = K
    for index in range(32):
        round_key = key[0:64]
        round_keys.append(''.join(round_key))

        key = offset_bits(key)
        key = ''.join(key)
        sbox_res = s_box.get(key[0:4])
        key = key[4:]
        key = sbox_res + key
        xor_bits = key[60:65]
        xored_bits = xor_operation(xor_bits, round_counter)
        key = list(key)

        xored_bits = list(xored_bits)
        key[60] = xored_bits[0]
        key[61] = xored_bits[1]
        key[62] = xored_bits[2]
        key[63] = xored_bits[3]
        key[64] = xored_bits[4]
        round_counter += 1


def get_plaintext_blocks(input):
    global blocks
    bits = ''.join(format(ord(i), '08b') for i in input)
    #bits = input
    blocks = []
    while bits:
        blocks.append(bits[:64])
        bits = bits[64:]
    if len(blocks[-1]) < 64:
        for a in range(64 - len(blocks[-1])):
            blocks[-1] += '0'


def add_round_key(block, round_key):
    res = ''
    for x, y in zip(block, round_key):
        r = int(x) ^ int(y)
        res += str(r)
    return res


def make_subsitution(block):
    s_boxes = []
    changed_block = ''
    while block:
        s_boxes.append(block[:4])
        block = block[4:]
    for x in s_boxes:
        changed_block += s_box.get(x)
    return changed_block


def make_permutation(block):
    block = list(block)
    permutated_block = list(block)
    for index in range(64):
        permutated_block[int(p_box[index])] = block[index]
    return permutated_block


def encrypt():
    global blocks
    enc_d = ''
    encrypted_data = ''
    round_keys_arr = round_keys[:-1]
    for b in blocks:
        for rk in round_keys_arr:
            b = add_round_key(b, rk)
            b = make_subsitution(b)
            b = make_permutation(b)
        b = add_round_key(b, round_keys[31])
        encrypted_data += str(b)
    enc_data = []
    enc_d = encrypted_data
    while encrypted_data:
        enc_data.append((bin(int(encrypted_data[:8], 2))).encode())
        encrypted_data = encrypted_data[8:]
    hashed_data = ''
    for x in enc_data:
        hashed_data += str(binascii.b2a_uu(x))
    return enc_d


K = '00000000000000000000000000000000000000000000000000000000000000000000000000000000'
#K = '11111111111111111111111111111111111111111111111111111111111111111111111111111111'
print("KEY: " + str(K))

#plaintext = '0000000000000000000000000000000000000000000000000000000000000000'
#plaintext = '1111111111111111111111111111111111111111111111111111111111111111'
plaintext = 'Eloeloelo'

get_plaintext_blocks(plaintext)
generate_round_keys()
encrypted_data = encrypt()
print('\nencrypted data:\n')
print(encrypted_data)
print(hex(int(encrypted_data, 2)))
