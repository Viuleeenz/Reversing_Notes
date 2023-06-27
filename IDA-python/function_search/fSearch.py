import idaapi
import idautils


DEBUG = True

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
        "8D 55 E0 52 8D 45 E4 50 FF 15 CC 20 40 00",
        16,
        0)
    if res is None:
        print("[!] Pattern not Found")
        return None
    else:
        ea = idaapi.bin_search(address_start, address_end, pattern, idaapi.BIN_SEARCH_CASE)
        print("[+] Pattern found at: {0}".format(hex(ea)))
        return ea

def locate_decrypt_function(function_address):
    xref_list = []
    for xref in idautils.XrefsTo(function_address):
        if xref.frm not in xref_list:
            xref_list.append(xref.frm)
    return list(xref_list)



def gather_string_offset(xref_address):
    function_start = idc.get_func_attr(xref_address, FUNCATTR_START)
    new_address = xref_address
    while True:
        prev_address = idc.prev_head(new_address)
        if prev_address <= function_start:
            break
        #if idc.print_insn_mnem(prev_address) == "mov":
        #    if idc.print_operand(prev_address,1).split()[0] == "offset":
        #        return idc.get_operand_value(prev_address,1)
        if idc.print_insn_mnem(prev_address) == "push":
            if idc.print_operand(prev_address,0).split()[0] == "offset": 
                return idc.get_operand_value(prev_address, 0) 
        new_address = prev_address
    print("[!] Offset not found.")
    return None

def retrive_string(offset):
    obfuscated_string = ""
    counter = 0
    while chr(idaapi.get_byte(offset + counter)) != "\x00":
        obfuscated_string += chr(idaapi.get_byte(offset + counter))
        counter +=1
    return obfuscated_string

def deobfuscateString(data):
    string_array = data.split()
    deobfuscated_string = []
    i = 0
    key = "abcdefghilmnopqrstuvzy"
    for c in data:
        offset = key.find(c) - 5
        if offset < 0:
            offset = len(key) - abs(offset)
        deobfuscated_string.append(key[offset])
    return "".join(deobfuscated_string)

def add_comment(address, text):
    try:
        idc.set_cmt(address, text, 0)
        set_hexrays_comment(address, text)
    except:
        return

def main():
    text_segment_start, text_segment_end = get_text_segment()
    pattern_address = patternSearch(text_segment_start, text_segment_end)
    if pattern_address is not None:
        function_address = idaapi.get_func(pattern_address)
        xrefs = locate_decrypt_function(function_address.start_ea)
        for xref in xrefs:
            if DEBUG: 
                print("[+] Ref address usage: " + hex(xref))
            string_offset = gather_string_offset(xref)
            if string_offset != None:
                obfuscated_string = retrive_string(string_offset)
                if DEBUG:
                    print("[+] String offset: " + hex(string_offset))
                    print("[+] Obfuscated String: " + obfuscated_string)
                deob_string = deobfuscateString(obfuscated_string)
                print("Deobfuscated String: " + deob_string)    
                add_comment(string_offset, deob_string)


if __name__ == "__main__":
    main()
