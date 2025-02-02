import struct

instr_name = {}


instr_name['cb'] = [[0x34, 0x35, 0xb4, 0xb5]]
instr_name['ret'] = [[0xd6], [0x5f]]
instr_name['bl'] = [[0x94, 0x97]]
instr_name['b'] = [[0x14]]
instr_name['tb'] = [[0x37]]
instr_name['b.cc'] = [[0x54]]
instr_name['brk'] = [[0xd4]]
instr_name['ldr'] = [[0x18]]
instr_name['adrp'] = [[0x90, 0xb0, 0xd0, 0xf0]]
instr_name['add_imm'] = [[0x91, 0x11]]
instr_name['add_lsl'] = [[0x8b]]
instr_name['ldr_imm'] = [[0xb8, 0xb9, 0xf8, 0xf9]]
instr_name['ldr_lit'] = [[0x18, 0x58]]
instr_name['mov'] = [[0x52]]


op_instr = {}
op_instr_ext = {}
op_instr_ext_64 = {}


instr_name_ext = {}
instr_name_ext_64 = {}


def build_instructions(definitions, instr_dict):
    for cinstr in definitions:
        op_base = [instr_dict]
        nop_base = []
        for op_list in definitions[cinstr]:
            for cop_base in op_base:
                for copcode in op_list:
                    if copcode not in cop_base:
                        cop_base[copcode] = {}
                    nop_base.append(cop_base[copcode])
            op_base = nop_base
            nop_base = []
        for cbase in op_base:
            cbase['i'] = cinstr
    return


build_instructions(instr_name, op_instr)
build_instructions(instr_name_ext, op_instr_ext)
build_instructions(instr_name_ext, op_instr_ext_64)
build_instructions(instr_name_ext_64, op_instr_ext_64)


class LDE():
    cpu_base = 64
    operand_size = 32

    def __init__(self, bitness):
        self.disas_func = self.get_function_instructions
        self.cpu_base = bitness

    def decode_instr(self, datas_to_decode, extended_decode=False):
        if not datas_to_decode or len(datas_to_decode) < 4:
            return [None, None]
        opcodes = datas_to_decode[0:4][::-1]
        size = 4
        name = None
        clayer = op_instr
        i = 0
        while opcodes[i] in clayer:
            clayer = clayer[opcodes[i]]
            if 'i' in clayer:
                name = clayer['i']
            i += 1
        return [size, name]

    def get_function_instructions(self, address, cb_read=None, max_instr=0x1000, extended_decode=False):
        to_disas = [address]
        instr_list = {}
        instr_count = 0

        while to_disas:
            if max_instr <= instr_count:
                break
            caddress = to_disas.pop()
            if caddress in instr_list:
                continue
            stop_exec = False
            if caddress is None:
                continue
            datas = cb_read(caddress, 0x10)
            if datas is None or len(datas) < 1 or datas.startswith(b"\x00\x00\x00\x00"):
                continue
            instr_size, instr_name = self.decode_instr(datas, extended_decode)
            if instr_size is None:
                return instr_list
            instr_list[caddress] = [instr_size]
            if instr_name is not None:
                infos = {'name': instr_name}
                if instr_name == 'b.cc' or instr_name == 'tb':
                    base_val = struct.unpack('I', datas[:4])[0]
                    rel_jmp = ((base_val & 0xffffff) >> 3) & 0xfffffc
                    if rel_jmp & 0x100000:
                        rel_jmp = -(0x100000-(0xfffff & rel_jmp))
                    to_disas.append(caddress+rel_jmp)
                    infos['dst_addr'] = caddress+rel_jmp
                elif instr_name == 'cb':
                    base_val = struct.unpack('I', datas[:4])[0]
                    rel_jmp = ((base_val & 0xffffff) >> 3) & 0xfffffc
                    if rel_jmp & 0x100000:
                        rel_jmp = -(0x100000-(0xfffff & rel_jmp))
                    to_disas.append(caddress+rel_jmp)
                    infos['dst_addr'] = caddress+rel_jmp
                elif instr_name == 'b':
                    rel_jmp = (struct.unpack('I', datas[:4])[0] & 0xffffff) << 2
                    if rel_jmp & 0x2000000:
                        rel_jmp = -(0x2000000-(0x1ffffff & rel_jmp))
                    to_disas.append(caddress+rel_jmp)
                    infos['dst_addr'] = caddress+rel_jmp
                    stop_exec = True
                elif instr_name == 'bl':
                    opcode = datas[3]
                    rel_jmp = (struct.unpack('I', datas[:4])[0] & 0xffffff) << 2
                    if opcode == 0x97:
                        rel_jmp = -(0x4000000-(0x3ffffff & rel_jmp))
                    infos['dst_addr'] = caddress+rel_jmp
                elif instr_name == 'brk':
                    stop_exec = True
                elif instr_name == 'ret':
                    stop_exec = True
                elif instr_name == 'ldr_imm':
                    base_val = struct.unpack('I', datas[:4])[0]
                    opcode = base_val >> 24
                    if opcode == 0xb9 or opcode == 0xf9:
                        if opcode == 0xf9:
                            imm = (base_val & 0x3ffc00) >> 7
                        else:
                            imm = (base_val & 0x3ffc00) >> 8
                        infos['imm'] = imm
                        infos['reg_dst'] = base_val & 0x1f
                        infos['reg_src'] = (base_val & 0x3e0) >> 5
                    if opcode == 0xb8 or opcode == 0xf8:
                        imm = (base_val & 0x1ff000) >> 9
                        if imm & 0x100:
                            imm = -(0x200-(0x1ff & imm))
                        infos['imm'] = imm
                        infos['reg_dst'] = base_val & 0x1f
                        infos['reg_src'] = (base_val & 0x3e0) >> 5
                elif instr_name == 'ldr_lit':
                    base_val = struct.unpack('I', datas[:4])[0]
                    opcode = base_val >> 24
                    if opcode == 0x58 or opcode == 0x18:
                        imm = (base_val & 0xffffe0) >> 5
                        infos['imm'] = imm
                        infos['reg_dst'] = base_val & 0x1f
                elif instr_name == 'add_imm':
                    base_val = struct.unpack('I', datas[:4])[0]
                    val_add = (base_val & 0x3fffff) >> 10
                    infos['imm'] = val_add
                    infos['reg_dst'] = base_val & 0x1f
                    infos['reg_src'] = (base_val & 0x3e0) >> 5
                elif instr_name == 'adrp':
                    opcode = datas[3]
                    base_val = struct.unpack('I', datas[:4])[0]
                    val = (base_val & 0xffffe0) << 9
                    inc_page = (opcode & 0x60) << 7
                    val += inc_page
                    if val & 0x100000000:
                        val = -(0x100000000-(0xffffffff & val))
                    val = ((caddress & 0xfffffffffffff000) + val) & 0xffffffffffffffff
                    infos['value'] = val
                    infos['reg_dst'] = base_val & 0x1f
                instr_list[caddress].append(infos)
            if not stop_exec:
                to_disas.append(caddress+instr_size)
            instr_count += 1

        return instr_list
