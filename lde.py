import struct

instr_name = {}

instr_name['jcc_short'] = [[0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f]]
instr_name['jcc_long'] = [[0x0f], [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f]]
instr_name['ret'] = [[0xc2, 0xc3]]
instr_name['jmp_short'] = [[0xeb]]
instr_name['jmp_long'] = [[0xe9]]
instr_name['int3'] = [[0xcc]]
instr_name['call'] = [[0xe8]]
instr_name['call_ptr'] = [[0xff], [0x15]]

op_instr = {}
op_instr_ext = {}
op_instr_ext_64 = {}


instr_name_ext = {}
instr_name_ext_64 = {}

ext_prefix = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f]

instr_name_ext['xor_imm8'] = [[0x83], [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]]
instr_name_ext_64['xor_imm8'] = [ext_prefix, [0x83], [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]]

instr_name_ext['xor_imm32'] = [[0x81], [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]]  # xor REG, imm8
instr_name_ext_64['xor_imm32_ext'] = [ext_prefix, [0x81], [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7]]

instr_name_ext['xor_ptr_imm8'] = [[0x80], [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37]]  # xor [REG], imm8
instr_name_ext_64['xor_ptr_imm8'] = [ext_prefix, [0x80], [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37]]  # xor [REG], imm8

instr_name_ext['xor_ptr_imm32'] = [[0x81], [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37]]  # xor [REG], imm32
instr_name_ext_64['xor_ptr_imm32'] = [ext_prefix, [0x81], [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37]]  # xor [REG], imm32


instr_name_ext['xor_reg'] = [[0x31]]  # xor REG
instr_name_ext['xor_eax_esp'] = [[0x31], [0xe0]]  # xor REG
instr_name_ext_64['xor_eax_esp_ext'] = [[0x48], [0x31], [0xe0]]  # xor REG
instr_name_ext['xor_same_reg'] = [[0x31], [0xc0, 0xdb, 0xc9, 0xd2, 0xed, 0xe4, 0xf6, 0xff]]  # xor REG, REG
instr_name_ext_64['xor_same_reg'] = [[0x31], [0xc0, 0xdb, 0xc9, 0xd2, 0xed, 0xe4, 0xf6, 0xff]]  # xor REG, REG
instr_name_ext_64['xor_reg'] = [ext_prefix, [0x31]]  # xor REG
instr_name_ext_64['xor_same_reg_ext'] = [ext_prefix, [0x31], [0xc0, 0xdb, 0xc9, 0xd2, 0xed, 0xe4, 0xf6, 0xff]]  # xor REG, REG

instr_name_ext_64['lea_rip_plus'] = [[0x8d], [0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d]]  # lea REG
instr_name_ext_64['lea_rip_plus_ext'] = [ext_prefix, [0x8d], [0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d]]  # lea REG


instr_name_ext['mov_imm32'] = [[0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc7]]

instr_name_ext['push_imm32'] = [[0x68]]

instr_name_ext['add_eax_imm32'] = [[0x05]]

instr_name_ext['add_imm32'] = [[0x81], [0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7]]

instr_name_ext_64['add_rsp'] = [[0x48], [0x81, 0x83], [0xc4]]
instr_name_ext_64['pop_rbp'] = [[0x5d]]
instr_name_ext['leave'] = [[0xc9]]
instr_name_ext['pop'] = [[0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f]]
instr_name_ext_64['pop_ext'] = [ext_prefix, [0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f]]
instr_name_ext['jcc_short'] = [[0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f]]
instr_name_ext['jcc_long'] = [[0x0f], [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f]]
instr_name_ext['ret'] = [[0xc2, 0xc3]]
instr_name_ext['jmp_short'] = [[0xeb]]
instr_name_ext['jmp_long'] = [[0xe9]]
instr_name_ext['int3'] = [[0xcc]]
instr_name_ext['call'] = [[0xe8]]
instr_name_ext['call_ptr'] = [[0xff], [0x15]]
instr_name_ext_64['call_ptr_ext'] = [ext_prefix, [0xff], [0x15]]
instr_name_ext['jmp_ptr'] = [[0xff], [0x25]]
instr_name_ext_64['jmp_ptr_ext'] = [ext_prefix, [0xff], [0x25]]


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
        self.base_opcodes = [self.f1_, self.f1_, self.f1_, self.f1_, self.f3_, self.f6_, self.f5_, self.f5_, self.f1_, self.f1_, self.f1_, self.f1_, self.f3_, self.f6_, self.f5_, self.esc_2byte, self. f1_, self.f1_, self.f1_, self.f1_, self.f3_, self.f6_, self.f5_, self.f5_, self.f1_, self.f1_, self.f1_, self.f1_, self.f3_, self.f6_, self.f5_, self.f5_, self.f1_, self.f1_, self.f1_, self.f1_, self.f3_, self.f6_, self.f12_, self.f5_, self.f1_, self.f1_, self.f1_, self.f1_, self.f3_, self.f6_, self.f12_, self.f5_, self.f1_, self.f1_, self.f1_, self.f1_, self.f3_, self.f6_, self.f12_, self.f5_, self.f1_, self.f1_, self.f1_, self.f1_, self.f3_, self.f6_, self.f12_, self.f5_, self. f11_, self.f11_, self.f11_, self.f11_, self.f11_, self.f11_, self.f11_, self.f11_, self.f10_, self.f10_, self.f10_, self.f10_, self.f10_, self.f10_, self.f10_, self.f10_, self.  f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self. f2_, self.f2_, self.f17_, self.f1_, self.f12_, self.f12_, self.prefOpSize, self. prefAdSize, self. push_Iv, self.imul_GvEvIv, self. f3_, self.f8_, self.f2_, self.f2_, self.f2_, self.f2_, self. f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self. f8_, self.g1_EvIv, self.g1_EbIb2, self.f8_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.pop_Ev, self. f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.callF_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self. f20_, self.f21_, self.f20_, self.f21_, self.f2_, self.f2_, self.f2_, self.f2_, self.f3_, self.f6_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self. f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f6_, self.f6_, self.f6_, self.f6_, self.f6_, self.f6_, self.f6_, self.f6_, self. f8_, self.f8_, self.f19_, self.f2_, self.f17_, self.f17_, self.f8_, self.f13_, self.f15_, self.f2_, self.f19_, self.f2_, self.f2_, self.f3_, self.f5_, self.f2_, self. f1_, self.f1_, self.f1_, self.f1_, self.f14_, self.f14_, self.f2_, self.f2_, self.d8_, self.d9_, self.da_, self.db_, self.dc_, self.dd_, self.de_, self.df_, self. f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f3_, self.f6_, self.f6_, self.jmp_far, self.f3_, self.f2_, self.f2_, self.f2_, self.f2_, self. f12_, self.f2_, self.prefREPNE, self.prefREP, self.f2_, self.f2_, self.g3_Eb, self.g3_Ev, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.g4_IncDec, self.g5_IncDec]
        self.base_opcodes_2 = [self.g6_, self.g7_, self.f1_, self.f1_, self.echec_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.echec_, self.f2_, self.echec_, self.f1_, self.f2_, self.echec_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.g16_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f18_, self.f18_, self.f18_, self.f18_, self.echec_, self.echec_, self.echec_, self.echec_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.echec_, self.echec_, self.esc_tableA4, self.echec_, self.esc_tableA5, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f4_, self.f4_, self.f1_, self.f1_, self.f1_, self.g12_, self.g13_, self.g14_, self.f1_, self.f1_, self.f1_, self.f2_, self.f1_, self.f1_, self.echec_, self.echec_, self.f1_, self.f1_, self.f1_, self.f1_, self.f6_, self.f6_, self.f16_, self.f16_, self.f16_, self.f16_, self.f6_, self.f6_, self.f6_, self.f6_, self.f6_, self.f6_, self.f6_, self.f6_, self.f6_, self.f6_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f2_, self.f2_, self.f2_, self.f1_, self.f8_, self.f1_, self.echec_, self.echec_, self.f2_, self.f2_, self.f2_, self.f1_, self.f8_, self.f1_, self.g15_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f2_, self.g8_EvIb, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.g9_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f2_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f23_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f23_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.lddqu_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.echec_]
        self.base_opcodes_3 = [self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.f1_, self.echec_, self.echec_, self.echec_, self.echec_, self.f4_, self.echec_, self.echec_, self.echec_, self.f4_, self.f4_, self.echec_, self.f4_, self.echec_, self.echec_, self.echec_, self.echec_, self.f1_, self.f1_, self.f1_, self.echec_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.echec_, self.echec_, self.f4_, self.f4_, self.f4_, self.f4_, self.echec_, self.echec_, self.echec_, self.echec_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.echec_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.f22_, self.f22_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_]
        self.base_opcodes_4 = [self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f4_, self.f1_, self.echec_, self.echec_, self.echec_, self.echec_, self.f4_, self.f4_, self.f4_, self.f4_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.f4_, self.f4_, self.f4_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.f4_, self.f4_, self.f4_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.f4_, self.f4_, self.f4_, self.f4_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_, self.echec_]
        self.modRm = [self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.addr_SIB, self.addr_disp32, self.addr_ESI, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.addr_SIB, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.addr_SIB, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing, self.do_nothing]
        self.disas_func = self.get_function_instructions
        self.cpu_base = bitness

    def f1_(self, datas):
        size = 2
        size += self.mod_rm(datas[1:])
        return size

    def f2_(self, datas):
        size = 1
        return size

    def f3_(self, datas):
        size = 2
        return size

    def f4_(self, datas):
        if self.operand_size == 16:
            size = self.f1_(datas)
        else:
            size = 1
        return size

    def f5_(self, datas):
        """ Do something with 64b"""
        size = 1
        return size

    def f6_(self, datas):
        if self.operand_size >= 32:
            size = 5
        else:
            size = 3
        return size

    def f7_(self, datas):
        if self.operand_size == 64:
            size = 9
        elif self.operand_size == 32:
            size = 5
        else:
            size = 3
        return size

    def f8_(self, datas):
        size = self.f1_(datas)
        size += 1
        return size

    def f10_(self, datas):
        if self.cpu_base == 64:
            self.operand_size = 64
            size = 1
            idx = datas[1]
            size += self.base_opcodes[idx](datas[1:])
        else:
            size = 1
        return size

    def f11_(self, datas):
        if self.cpu_base == 64:
            size = 1
            idx = datas[1]
            size += self.base_opcodes[idx](datas[1:])
        else:
            size = 1
        return size

    def f12_(self, datas):
        size = 1
        size += self.base_opcodes[datas[1]](datas[1:])
        return size

    def f13_(self, datas):
        if self.operand_size >= 32:
            size = self.f1_(datas)
            size += 4
        else:
            size = self.f1_(datas)
            size += 2
        return size

    def f14_(self, datas):
        if self.cpu_base == 64:
            size = 1
        else:
            size = 2
        return size

    def f15_(self, datas):
        size = 4
        return size

    def f16_(self, datas):
        size = 5
        return size

    def f17_(self, datas):
        if self.cpu_base == 64:
            size = 1
        else:
            size = self.f1_(datas)
        return size

    def f18_(self, datas):
        """ To review """
        size = 1
        return size

    def f19_(self, datas):
        size = 3
        return size

    def f20_(self, datas):
        if self.cpu_base == 64:
            size = 9
        else:
            size = 5
        return size

    def f21_(self, datas):
        if self.cpu_base == 16:
            size = 3
        elif self.cpu_base == 32:
            size = 5
        else:
            size = 9
        return size

    def f22_(self, datas):
        size = self.f1_(datas)
        return size

    def f23_(self, datas):
        size = self.f1_(datas)
        return size

    def g1_EvIv(self, datas):
        size = self.f1_(datas)
        if self.cpu_base == 64:
            size += 4
        else:
            size += 2
        return size

    def g1_EbIb2(self, datas):
        size = 1
        return size

    def callF_(self, datas):
        if self.cpu_base == 64:
            if self.operand_size == 32:
                size = 7
            else:
                size = 5
        else:
            size = 1
        return size

    def jmp_far(self, datas):
        if self.cpu_base == 64:
            if self.operand_size == 32:
                size = 7
            else:
                size = 5
        else:
            size = 1
        return size

    def prefREPNE(self, datas):
        size = self.base_opcodes[datas[1]](datas[1:])
        return size

    def prefREP(self, datas):
        size = self.base_opcodes[datas[1]](datas[1:])
        return size

    def d8_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def d9_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def da_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def db_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def dc_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def dd_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def de_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def df_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def esc_2byte(self, datas):
        size = 1
        size += self.base_opcodes_2[datas[1]](datas[1:])
        return size

    def prefOpSize(self, datas):
        self.operand_size = 16
        size = 1
        size += self.base_opcodes[datas[1]](datas[1:])
        self.operand_size = 32
        return size

    def prefAdSize(self, datas):
        if self.operand_size == 32 or self.operand_size == 64:
            self.operand_size = self.operand_size >> 1
        else:
            return 1
        size = 1
        size += self.base_opcodes[datas[1]](datas[1:])
        if self.operand_size == 32 or self.operand_size == 16:
            self.operand_size = self.operand_size << 1
        else:
            return 1
        return size

    def push_Iv(self, datas):
        if self.cpu_base >= 32:
            size = 5
        else:
            size = 3
        return size

    def imul_GvEvIv(self, datas):
        if self.operand_size != 16:
            size = self.mod_rm(datas)
            size += 6
        else:
            size = self.mod_rm(datas)
            size += 4
        return size

    def pop_Ev(self, datas):
        size = self.f1_(datas)
        return size

    def pop_Iv(self, datas):
        if self.cpu_base == 64 or self.cpu_base == 32:
            size = 5
        else:
            size = 3
        return size

    def g3_Eb(self, datas):
        opcode = datas[1]
        reg_mask = (opcode & 0b00111000) >> 3
        size = self.mod_rm(datas)
        size += 1
        if reg_mask == 0:
            size += 3
            return size
        if reg_mask == 1:
            return size
        size += 2
        return size

    def g3_Ev(self, datas):
        if self.operand_size == 64:
            size = self.mod_rm(datas)
            opcode = datas[1]
            reg_mask = (opcode & 0b00111000) >> 3
            if reg_mask == 0:
                size += 6
                return size
            if reg_mask == 1:
                size += 1
                return size
            size += 2
        else:
            size = self.mod_rm(datas)
            reg_mask = (datas[1] & 0b00111000) >> 3
            if reg_mask == 0:
                size += 4
                return size
            if reg_mask == 1:
                size += 1
                return size
            size += 2
        return size

    def g4_IncDec(self, datas):
        size = self.mod_rm(datas)
        reg_mask = (datas[0] & 0b00111000) >> 3
        if reg_mask == 1:
            size += 1
            return size
        size += 2
        return size

    def g6_(self, datas):
        size = self.mod_rm(datas)
        reg_mask = (datas[0] & 0b00111000) >> 3
        if reg_mask <= 5:
            size += 2
        return size

    def g7_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def g8_EvIb(self, datas):
        size = 3
        return size

    def g9_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def g12_(self, datas):
        size = self.mod_rm(datas)
        size += 3
        return size

    def g13_(self, datas):
        size = self.mod_rm(datas)
        size += 3
        return size

    def g14_(self, datas):
        size = self.mod_rm(datas)
        size += 3
        return size

    def g15_(self, datas):
        size = 2
        return size

    def g16_(self, datas):
        size = self.mod_rm(datas)
        size += 2
        return size

    def lddqu_(self, datas):
        size = self.f1_(datas)
        return size

    def esc_tableA4(self, datas):
        size = self.base_opcodes_3[datas[1]](datas[1:])
        return size

    def esc_tableA5(self, datas):
        size = self.base_opcodes_4[datas[1]](datas[1:])
        return size

    def echec_(self, datas):
        size = 1
        return size

    def g5_IncDec(self, datas):
        size = self.mod_rm(datas[1:])
        size += 2
        return size

    def addr_SIB(self, datas):
        opcode = datas[0]
        size = 1
        base_mask = opcode & 0b00000111
        if base_mask == 5:
            size += 4
        return size

    def mod_rm(self, datas):
        opcode = datas[0]
        rm_mask = opcode & 0b00000111
        mod_mask = (opcode & 0b11000000) >> 6
        size = 0
        if mod_mask == 1:
            size += 1
        elif mod_mask == 2:
            size += 4
        idx = (mod_mask << 3) | rm_mask
        size += self.modRm[idx](datas[1:])
        return size

    def do_nothing(self, datas):
        return 0

    def addr_disp32(self, datas):
        return 4

    def addr_ESI(self, datas):
        return 0

    def decode_instr(self, datas_to_decode, extended_decode=False):
        if len(datas_to_decode) <= 0:
            return [None, None]
        opcode = datas_to_decode[0]
        func = self.base_opcodes[opcode]
        size = func(datas_to_decode)
        name = None
        if not extended_decode:
            clayer = op_instr
            i = 0
            while datas_to_decode[i] in clayer:
                clayer = clayer[datas_to_decode[i]]
                if 'i' in clayer:
                    name = clayer['i']
                i += 1
        else:
            if self.operand_size == 32:
                clayer = op_instr_ext
            else:
                clayer = op_instr_ext_64
            i = 0
            while datas_to_decode[i] in clayer:
                clayer = clayer[datas_to_decode[i]]
                if 'i' in clayer:
                    name = clayer['i']
                i += 1
        return [size, name]

    def get_function_instructions(self, address, cb_read=None, max_instr=0x1000, extended_decode=False):
        to_disas = [address]
        instr_list = {}
        instr_count = 0

        while len(to_disas) > 0:
            if max_instr <= instr_count:
                break
            caddress = to_disas.pop()
            if caddress in instr_list:
                continue
            stop_exec = False
            if caddress is None:
                continue
            datas = cb_read(caddress, 0x10)
            if datas is None or len(datas) < 1 or datas == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00":
                continue
            try:
                instr_size, instr_name = self.decode_instr(datas, extended_decode)
                self.operand_size = 32
            except Exception as e:
                print(e)
                instr_size = None
                self.operand_size = 32
            if instr_size is None:
                return instr_list
            instr_list[caddress] = [instr_size]
            if instr_name is not None:
                instr_list[caddress].append(instr_name)
                if instr_name == 'jcc_short':
                    to_disas.append(caddress+instr_size)
                    rel_jmp = datas[1]
                    if (rel_jmp & 0x80) != 0:
                        rel_jmp = -(0x80-(0x7f & rel_jmp))
                    to_disas.append(caddress+instr_size+rel_jmp)
                    instr_list[caddress].append(caddress+instr_size+rel_jmp)
                elif instr_name == 'jcc_long':
                    to_disas.append(caddress+instr_size+struct.unpack('i', datas[2:6])[0])
                    instr_list[caddress].append(caddress+instr_size+struct.unpack('i', datas[2:6])[0])
                elif instr_name == 'jmp_short':
                    rel_jmp = datas[1]
                    if (rel_jmp & 0x80) != 0:
                        rel_jmp = -(0x80-(0x7f & rel_jmp))
                    to_disas.append(caddress+instr_size+rel_jmp)
                    instr_list[caddress].append(caddress+instr_size+rel_jmp)
                    stop_exec = True
                elif instr_name == 'jmp_long':
                    to_disas.append(caddress+instr_size+struct.unpack('i', datas[1:5])[0])
                    instr_list[caddress].append(caddress+instr_size+struct.unpack('i', datas[1:5])[0])
                    stop_exec = True
                elif instr_name == 'call':
                    instr_list[caddress].append(caddress+instr_size+struct.unpack('i', datas[1:5])[0])
                elif instr_name.startswith('call_ptr'):
                    ptr = caddress+instr_size+struct.unpack('i', datas[instr_size-4:instr_size])[0]
                    if self.cpu_base == 64:
                        ptr_datas = cb_read(caddress+instr_size+ptr, 8)
                    else:
                        ptr_datas = datas[2:6]
                    if ptr_datas is not None:
                        if self.cpu_base == 64:
                            ptr = struct.unpack('Q', ptr_datas)[0]
                        else:
                            ptr = struct.unpack('I', ptr_datas)[0]
                    instr_list[caddress].append(ptr)
                elif instr_name.startswith('jmp_ptr'):
                    if self.cpu_base == 64:
                        ptr = caddress+instr_size+struct.unpack('i', datas[instr_size-4:instr_size])[0]
                        ptr_datas = cb_read(caddress+instr_size+ptr, 8)
                    else:
                        ptr_datas = datas[2:6]
                    if ptr_datas is not None:
                        if self.cpu_base == 64:
                            ptr = struct.unpack('Q', ptr_datas)[0]
                        else:
                            ptr = struct.unpack('I', ptr_datas)[0]
                        instr_list[caddress].append(ptr)
                    stop_exec = True
                elif instr_name.startswith('push_imm32'):
                    if self.cpu_base == 32:
                        if len(datas) > 4:
                            instr_list[caddress].append(struct.unpack("I", datas[instr_size-4:instr_size])[0])
                elif instr_name.startswith('mov_imm32') or instr_name.startswith('add_imm32'):
                    if self.cpu_base == 32:
                        if len(datas) > 4:
                            instr_list[caddress].append(struct.unpack("I", datas[instr_size-4:instr_size])[0])
                    if self.cpu_base == 64:
                        if len(datas) > 4:
                            instr_list[caddress].append((caddress & 0xffffffff00000000)+struct.unpack("I", datas[instr_size-4:instr_size])[0])
                elif instr_name.startswith('lea_rip_plus'):
                    if len(datas) > 4:
                        instr_list[caddress].append(caddress+instr_size+struct.unpack("i", datas[instr_size-4:instr_size])[0])
                elif instr_name == 'add_rsp':
                    if datas[1] == 0x81:
                        instr_list[caddress].append(struct.unpack("I", datas[3:7])[0])
                    elif datas[1] == 0x83:
                        instr_list[caddress].append(datas[3])
                elif instr_name == 'int3':
                    stop_exec = True
                elif instr_name == 'ret':
                    if datas[0] == 0xc2:
                        instr_list[caddress].append(struct.unpack("H", datas[1:3])[0])
                    else:
                        instr_list[caddress].append(0)
                    stop_exec = True
            if not stop_exec:
                to_disas.append(caddress+instr_size)
            instr_count += 1

        return instr_list
