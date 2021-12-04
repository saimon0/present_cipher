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


rp_box = [
    '0', '16', '32', '48', '1', '17', '33', '49',
    '2', '18', '34', '50', '3', '19', '35', '51',
    '4', '20', '36', '52', '5', '21', '37', '53',
    '6', '22', '38', '54', '7', '23', '39', '55',
    '8', '24', '40', '56', '9', '25', '41', '57',
    '10', '26', '42', '58', '11', '27', '43', '59',
    '12', '28', '44', '60', '13', '29', '45', '61',
    '14', '30', '46', '62', '15', '31', '47', '63',
]


K = ''
blocks = []
round_keys = []
round_counter = 1


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
    if input.isdigit():
        bits = input
    else:
        bits = ''.join(format(ord(i), '08b') for i in input)
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
        changed_block += s_box.get(str(x))
    return changed_block


def make_permutation(block):
    block = list(block)
    permutated_block = list(block)
    for index in range(64):
        permutated_block[int(p_box[index])] = block[index]
    return permutated_block


def reverse_permutation(block):
    block = list(block)
    repermutated_block = list(block)
    for index, p_index in enumerate(p_box):
        repermutated_block[int(index)] = block[int(p_index)]
    return repermutated_block


def find_key(input_dict, value):
    result = "None"
    for key, val in input_dict.items():
        if val == value:
            result = key
    return result


def reverse_subsitution(block):
    s_boxes = []
    changed_block = ''
    while block:
        s_boxes.append(block[:4])
        block = block[4:]
    for x in s_boxes:
        reversed_sub = find_key(s_box, str(x))
        changed_block += str(reversed_sub)
    return changed_block


def encrypt():
    get_plaintext_blocks(plaintext)
    generate_round_keys()
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


def decrypt(ciphertext):
    global round_keys
    ct_arr = []
    decrypted_data = ''
    round_keys_arr = round_keys[1:]
    while ciphertext:
        ct_arr.append(ciphertext[:64])
        ciphertext = ciphertext[64:]
    for b in ct_arr:
        for rk in reversed(round_keys_arr):
            b = add_round_key(b, rk)
            b = reverse_permutation(b)
            b = reverse_subsitution(''.join(b))
        add_round_key(b, round_keys[0])
        decrypted_data += str(b)
    return decrypted_data


def binary_to_ascii(text):
    text_arr = []
    while text:
        text_arr.append(text[:8])
        text = text[8:]
    for i, x in enumerate(text_arr):
        text_arr[i] = chr(int(x[:8], 2))
    ascii_text = ''.join(text_arr).rstrip('\x00')
    return ascii_text


def verify_key_length(key):
    if len(key) != 80 or not isinstance(key, int):
        print("Key must be 10 integer-digit number!")

K = '00000000000000000000000000000000000000000000000000000000000000000000000000000000'

plaintext = 'tajna wiadomosc zaszyfrowana szyfrem PRESENT'


encrypted_data = encrypt()

print("\nKEY: " + str(K))
print("PLAINTEXT: " + str(plaintext))
print("\nCIPHERTEXT (BIN): " + str(encrypted_data))
print("CIPHERTEXT (HEX): " + hex(int(encrypted_data, 2)))

decrypted_data = decrypt(encrypted_data)

print("\nDECRYPTED PLAINTEXT (BIN): " + str(decrypted_data))
print("DECRYPTED PLAINTEXT (ASCII): " + (binary_to_ascii(decrypted_data)))
