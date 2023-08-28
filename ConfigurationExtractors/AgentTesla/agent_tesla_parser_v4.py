import sys
import struct
from dotnetfile import DotNetPE

def xor_crypt(ciphertext, key_byte):
    plaintext = []
    for c in ciphertext:
        plaintext.append(c ^ key_byte)
    return bytes(plaintext)

def decrypt(data):
    decrypted_strings = []
    ptr = 4
    while ptr < len(data):
        size = struct.unpack('<I', data[ptr:ptr+4])[0]
        ptr += 4
        key = data[ptr:ptr+1]
        ptr += 4
        str_data = data[ptr:ptr+size]
        ptr += size
        out = xor_crypt(str_data[::-1], ord(key))
        if not out.isascii():
            break
        decrypted_strings.append(out)
    return decrypted_strings

def main():
    if len(sys.argv) < 2:
        print("Error in argument file")
        sys.exit(1)
    file_path = sys.argv[1]
    d_file = DotNetPE(file_path)
    md_tables = d_file.metadata_tables

    class_sizes = []
    for m in md_tables:
        if 'ClassLayout' in m.string_representation:
            class_layout_rows = m.table_rows
        if 'FieldRVA' in m.string_representation:
            field_rva_rows = m.table_rows

    for i in range(0, len(class_layout_rows)):
            class_sizes.append(class_layout_rows[i].ClassSize.value)
            
    encrypted_data_size = max(class_sizes)   
    
    physical_address = d_file.get_physical_by_rva(field_rva_rows[-1].RVA.value)
    data = d_file.get_data(physical_address, encrypted_data_size)
    print(decrypt(data))
    
if __name__ == '__main__':
    main()
