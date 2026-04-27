from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import *


class FuncExecutionEngine(SymbolicExecutionEngine):
    def __init__(self, ira):
        super().__init__(ira)
        self.jump = False

    def is_function_call_assignblk(self, assignblk):
        for dst, src in assignblk.items():
            instr = assignblk.instr
            if instr.name == "BL":
                if isinstance(src, ExprOp):
                    for i, arg in enumerate(src.args):
                        if isinstance(arg, ExprLoc):
                            return 1, arg
        return 0, False

    def eval_updt_irblock(self, irb, step=False):
        for assignblk in irb:
            instr = assignblk.instr
            offset = instr.offset
            if step:
                print(f"0x{offset:x}  ", instr)
                print('Assignblk:')
                print(assignblk)
                print('_' * 80)

            self.eval_updt_assignblk(assignblk)
            if step:
                self.dump(mems=False)
                self.dump(ids=False)
                print('=' * 80)

            status, is_jump = self.is_function_call_assignblk(assignblk)
            if status == 1:
                new_offset = 0
                for variable, value in viewitems(self.symbols.symbols_id):
                    if variable.name == "X0":
                        new_offset = value.args[0].arg
                self.symbols.symbols_id[ExprId("LR", 64)] = ExprInt(instr.offset + 4, 64)
                self.symbols.symbols_id[ExprId("PC", 64)] = ExprInt(new_offset, 64)
                self.jump = True
                return new_offset

        dst = self.eval_expr(self.lifter.IRDst)
        return dst

    def run_at_into_func(self, mdis, ira, addr, lbl_stop=None, step=False, deep=1):
        try:
            asm_cfg = mdis.dis_multiblock(addr)
        except TypeError:
            # 如果是 ExprCond，尝试获取其可能的具体值
            print(f"检测到符号跳转，地址表达式为: {addr}")
        ir_cfg = ira.new_ircfg_from_asmcfg(asm_cfg)

        while True:
            irblock = ir_cfg.get_block(addr)

            if irblock is None and deep:
                asm_cfg = mdis.dis_multiblock(addr)
                ir_cfg = ira.new_ircfg_from_asmcfg(asm_cfg)
                deep -= 1
                print("**************************************** [jump] ****************************************")
                continue

            if irblock is None and self.jump:
                self.jump = False
                asm_cfg = mdis.dis_multiblock(addr)
                ir_cfg = ira.new_ircfg_from_asmcfg(asm_cfg)
                print("**************************************** [ret] ****************************************")

                continue

            if irblock is None:
                break

            if irblock.loc_key == lbl_stop:
                break

            addr = self.eval_updt_irblock(irblock, step=step)
        return addr
