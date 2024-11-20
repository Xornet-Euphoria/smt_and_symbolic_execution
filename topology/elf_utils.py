from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from typing import Self


# not Xornet's ELF but eXtended ELF
class XELF(ELFFile):
    def __init__(self, stream, stream_loader=None, *, base_addr: int=0):
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.base_addr = base_addr  # not used now
        if isinstance(stream, str):
            stream = open(stream, "rb")
        super().__init__(stream, stream_loader)


    def get_bytes_from_address(self: Self, addr: int, size: int):
        g = self.address_offsets(addr)
        offset = next(g)
        f = self.stream

        # save offset
        current_file_offset = f.tell()
        f.seek(offset)
        ret = f.read(size)
        # recover offset
        f.seek(current_file_offset)

        return ret
    

    def disasm(self, addr: int, end: int):
        code = self.get_bytes_from_address(addr, end - addr)
        return self.md.disasm(code, addr)


# test
if __name__ == "__main__":
    elf = XELF("./topology")
    test_func = (0x2349, 0x4879)
    insns = elf.disasm(*test_func)

    for insn in insns:
        mnemonic = insn.mnemonic

        if mnemonic == "ret":
            print(insn)