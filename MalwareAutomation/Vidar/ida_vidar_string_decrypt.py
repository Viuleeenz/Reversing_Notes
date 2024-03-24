import idaapi
import idautils
import binascii

idaapi.msg_clear()
DEBUG = False

def get_text_segment(seg_name=".text"):
    for s in idautils.Segments():
        start = idc.get_segm_start(s)
        end = idc.get_segm_end(s)
        name = idc.get_segm_name(s)
        if name == seg_name:
            return start, end  

def patternSearch(address_start, address_end):
    segment_text_start, segment_text_end = get_text_segment(".text")
    pattern = idaapi.compiled_binpat_vec_t()
    
    res = idaapi.parse_binpat_str(
        pattern,
        address_start,
        "8A 0C 02 8B 55 08 8D 04 1E 32 0C 02 88 08",
        16,
        0)
    if res is None:
        print("[!] Pattern not Found")
        return None
    else:
        ea = idaapi.bin_search(address_start, address_end, pattern, idaapi.BIN_SEARCH_CASE)
        print("[+] Pattern found at: {0}".format(hex(ea)))
        return ea
 
def add_comment(address, text):
    try:
        idc.set_cmt(address, text, 0)
        set_hexrays_comment(address, text)
    except:
        return

def retrive_string(offset):
    encrypted_string = ""
    counter = 0
    while chr(idaapi.get_byte(offset + counter)) != "\x00":
        encrypted_string += chr(idaapi.get_byte(offset + counter))
        counter +=1
    return encrypted_string

def gather_string_offset(xref_address):
    to_decrypt = []
    push_call = 0
    DWORD_to_rename = ""
    function_start = idc.get_func_attr(xref_address, FUNCATTR_START)
    new_address = xref_address
    if DEBUG:
        print("[DEBUG] function start at: {0}".format(hex(function_start)))
    while True and push_call < 3:
        prev_address = idc.prev_head(new_address)
        if prev_address <= function_start:
            break
        if idc.print_insn_mnem(prev_address) == "mov" and idc.get_operand_type(prev_address,0) == idc.o_mem and idc.get_operand_type(prev_address,1) == idc.o_reg:
            DWORD_to_rename = idc.get_operand_value(prev_address, 0)
        if idc.print_insn_mnem(prev_address) == "push":
            push_call = push_call + 1
            if idc.print_operand(prev_address,0).split()[0] == "offset": 
                to_decrypt.append(idc.get_operand_value(prev_address, 0))
        new_address = prev_address
    if push_call == 3:
        if DEBUG:
            print("[DEBUG] Operands retrived \n[+] key offset :{1} | enc_str offset : {0}".format(hex(to_decrypt[0]), hex(to_decrypt[1])))
            print("[DEBUG] Address of renaming variable: {0}".format(API_to_rename))
        return to_decrypt, DWORD_to_rename
    return None

def decrypt(ciphertext, key): 
    plaintext = ''
    result = [ord(a) ^ ord(b) for a,b in zip(ciphertext, key)]
    for c in result:
        plaintext+=chr(c)
    print("[+] Original String: {0}  =>  Decoded String: {1}".format(ciphertext, plaintext))
    return plaintext

def locate_decrypt_function(function_address):
    xref_list = []
    for xref in idautils.XrefsTo(function_address):
        if xref.frm not in xref_list:
            xref_list.append(xref.frm)
    return list(xref_list)
 
def pointer_resolver(offset, name):
    idc.set_name(offset, "PTR_" + name, SN_NOWARN)

def string_resolver(offset, name):
    idc.set_name(offset, "_" + name, SN_NOWARN)

def main():
    text_segment_start, text_segment_end = get_text_segment()
    pattern_address = patternSearch(text_segment_start, text_segment_end)
    if pattern_address is not None:
        function_address = idaapi.get_func(pattern_address)
        xrefs = locate_decrypt_function(function_address.start_ea)
        for xref in xrefs:
            if DEBUG: 
                print("[DEBUG] Ref address: " + hex(xref))
            string_offset , DWORD_to_rename = gather_string_offset(xref)
            if string_offset != None:
                key = retrive_string(string_offset[1])
                encrypted_string = retrive_string(string_offset[0]) 
                decrypted_string = decrypt(encrypted_string, key)
                print("[-] Offset: {0}".format(hex(string_offset[0])))
                string_resolver(string_offset[0], decrypted_string)
                add_comment(string_offset[0], decrypted_string)
                pointer_resolver(string_offset[0], decrypted_string) 
                #if DWORD_to_rename:
                    
                

            

if __name__ == "__main__":
    main()
