"""
A tool to parse .obj file made by msvc
and generate them to shellcode byte array
    v0.1, developed by devseed
"""

import os
import struct
import codecs
from typing import Union, List, Dict

LIBSHELLCODE_VERSION = 100

class coff_filehdr_t(struct.Struct):
    def __init__(self, data):
        super().__init__('<2H3I2H')
        self.frombytes(data)

    def frombytes(self, data):
        (self.f_magic, self.f_nscns, 
         self.f_timedat, self.f_symptr, self.f_nsyms,
         self.f_opthdr, self.f_flags
         ) = self.unpack_from(data)
        pass

class coff_secthdr_t(struct.Struct):
    def __init__(self, data):
        super().__init__('<8s6I2HI')
        if data is not None:
            self.frombytes(data)

    def frombytes(self, data=None):
        (self.s_name, 
        self.s_paddr, self.s_vaddr, self.s_size, 
        self.s_scnptr, self.s_relptr,self.s_lnnoptr, 
        self.s_nreloc, self.s_nlnno,
        self.s_flags) = self.unpack_from(data)

class coff_syment_t(struct.Struct):
    def __init__(self, data=None):
        super().__init__('<8sIhH2B')
        if data is not None:
            self.frombytes(data)

    def frombytes(self, data=None):
        (self.n_name, self.n_value, 
        self.n_scnum, self.n_type, 
        self.n_sclass, self.n_numaux
        ) = self.unpack_from(data)

class Coff:
    def __init__(self, data=None):
        self.content = data
        if data is not None:
            self.parse(data)
    
    def parse(self, data):
        self.content = data
        self.filehdr = coff_filehdr_t(data)
        self.secthdrs = []
        self.syments = []

        offset = self.filehdr.size + self.filehdr.f_opthdr
        for i in range(self.filehdr.f_nscns):
            secthdr = coff_secthdr_t(data[offset:])
            offset += secthdr.size
            self.secthdrs.append(secthdr)

        offset = self.filehdr.f_symptr
        for i in range(self.filehdr.f_nsyms):
            syment = coff_syment_t(data[offset:])
            offset += syment.size
            self.syments.append(syment)
        
    def funcs(self):
        """
        generator for get functions informations
        :return: funcname, offset, size, content
        """
        data = self.content
        straddr = self.filehdr.f_symptr +\
             self.filehdr.f_nsyms * self.syments[0].size
        for i, syment in enumerate(self.syments):
            if not isinstance(syment, coff_syment_t):
                continue
            if syment.n_type!=0x20: continue # not function
            idx = syment.n_scnum # idx strart from 1
            if idx<=0: continue
            first, second =  struct.unpack("<II", syment.n_name)
            if first!=0:
                funcname = syment.n_name.decode().rstrip('\0')
            elif second!=0:
                addr = straddr+second
                size = data[addr:].find(b'\0')
                funcname = data[addr:addr+size].decode()
            else: continue

            # n_type 0x20, sz n_sclass=2, n_value is offset in sect
            secthdr = self.secthdrs[idx-1]
            if syment.n_type == 0x20 and syment.n_sclass==2:
                offset = secthdr.s_scnptr + syment.n_value
                size = secthdr.s_size - syment.n_value
                yield funcname, offset, size, \
                    data[offset: offset+size]

def extract_coff(objpath, killat=True) ->\
    Dict[str, bytes]:
    """
    parser all functions in coff obj format files
    use clang -c -O3 -ffunction-sections -fdata-sections
    :return: codes, {funcname: code}
    """
    print("extract_coff in", objpath)
    codes = dict()
    with open(objpath, 'rb') as fp:
        data = fp.read()
    coff = Coff(data)
    for funcname, offset, size, content in coff.funcs():
        print(f"{funcname}, addr=0x{offset:0x}, size=0x{size:0x}")
        if killat:
            start = 0
            if funcname[0] == '_': start = 1
            end = funcname.rfind('@')
            if end < 0: funcname = funcname[start:]
            else: funcname = funcname[start:end]
        codes.update({funcname: content})
    return codes

def code2arraystr(code: Union[bytes, List[int]],
    format="c") -> str: 
    
    arraystr = ""
    if format.lower() == "c":
        arraystr = ",".join(
            [f'0x{x:02x}' for x in code])
    elif format.lower() == "py" :
        arraystr = "".join(
            [f'\\x{x:02x}' for x in code])
    elif format.lower() == "hex":
        arraystr = " ".join(
            [f'{x:02x}' for x in code])
    else: 
        raise NotImplementedError(
            f"unkonw format{format}")
    return arraystr

def arraystr2code(arraystr:str, format="c")->List[int]:
    code = []
    if format.lower() == "c":
        tokens = arraystr.split(',')
        for token in tokens:
            try:
                code.append(
                    eval(token.strip(' ')))
            except SyntaxError:
                code.append(
                    eval(token.strip(' ').lstrip('0')))
    elif format.lower() == "py":
        code = list(eval(f"b'{arraystr}'"))
    elif format.lower() == "hex":
        for i, c in enumerate(
                arraystr.replace(' ', '')):
            if i%2==0: c0 = c
            else: code.append(int(c0 + c, 16))
    else: 
        raise NotImplementedError(
            f"unkonw format{format}")
    return code

def write_shellcode_header(
    codes: Dict[str, Union[List[int], bytes]], /, outname="", outpath="", 
    onlycode=False ) -> List[str]:
    """
    write the shell code to .h file
    :param: codes, {name: code}
    :return: .h content lines
    """
    if outname=="":
        outname = os.path.basename(outpath)
        outname = os.path.splitext(outname)[0]

    if not onlycode: lines = ["/* Automatic generated by shellcode.py, "
        "do not modify this file!*/",
        "#ifndef _" + outname.upper() + "_H",
        "#define _" + outname.upper() + "_H"]
    else: lines = []
    for (name, code) in codes.items():
        codestr = ",".join([f'0x{x:02x}' for x in code])
        lines.append(f'unsigned char {name}[] = {{{codestr}}};')
    if not onlycode: lines.extend(["#endif"])

    if outpath != "":
        with codecs.open(outpath, 'w', 'utf8') as fp:
            fp.writelines(x + '\n' for x in lines)

    return lines

def test_codecvt():
    a0 = [1,2,3,4]
    a1 = code2arraystr(a0, "c")
    a2 = arraystr2code(a1, "c")
    print("test_codecvt c: ", a0, a1, a2)
    assert(a0 == a2)

    a1 = code2arraystr(a0, "py")
    a2 = arraystr2code(a1, "py")
    print("test_codecvt py: ", a0, a1, a2)
    assert(a0 == a2)

    a1 = code2arraystr(a0, "hex")
    a2 = arraystr2code(a1, "hex")
    print("test_codecvt hex: ", a0, a1, a2)
    assert(a0 == a2)
    
    aa = arraystr2code("0x22,  0x3,04, 0b1111, 235, 44, 0x22,33", "c")
    assert(aa == [0x22, 0x3, 4, 0b1111, 235, 44, 0x22, 33])
    print(aa)

def debug():
    test_codecvt()

def main():
    pass

if __name__ == '__main__':
    #debug()
    main()
    pass

"""
history:
v0.1, inital version parse .obj file
v0.1.1, add code2arraystr, arraystr2code
"""