#!/usr/bin/env python3
"""
QBDI Tracer Template for trace-ui (Python / pyqbdi)

生成 trace-ui 兼容的 QBDI ARM64 trace 日志。

输出格式：
  0xADDR module+0xOFF: disasm; reg=val ... mem_r=addr/mem_w=addr -> reg=val ...

用法：
  python3 qbdi-tracer-template.py > trace.txt

需要安装 pyqbdi:
  pip install pyqbdi
"""

import pyqbdi
import ctypes
import sys

GPR_NAMES = [
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
    "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "fp",  "lr",  "sp",
    "nzcv",
]

gpr_snapshot = None
output = sys.stdout


def pre_callback(vm, gpr, fpr, data):
    """保存执行前的寄存器状态。"""
    global gpr_snapshot
    gpr_snapshot = {}
    for i, name in enumerate(GPR_NAMES):
        gpr_snapshot[name] = pyqbdi.QBDI_GPR_GET(gpr, i)
    return pyqbdi.CONTINUE


def post_callback(vm, gpr, fpr, data):
    """在执行后输出 trace 行。"""
    global gpr_snapshot

    inst = vm.getInstAnalysis(
        pyqbdi.ANALYSIS_INSTRUCTION | pyqbdi.ANALYSIS_DISASSEMBLY | pyqbdi.ANALYSIS_SYMBOL
    )

    # 地址和反汇编
    addr = inst.address
    disasm = inst.disassembly or "???"
    module = inst.moduleName
    offset = inst.symbolOffset

    if module:
        line = f"0x{addr:x} {module}+0x{offset:x}: {disasm}"
    else:
        line = f"0x{addr:x}: {disasm}"

    # 收集执行前后的寄存器值
    pre_vals = gpr_snapshot or {}
    post_vals = {}
    for i, name in enumerate(GPR_NAMES):
        post_vals[name] = pyqbdi.QBDI_GPR_GET(gpr, i)

    # 找出变化的寄存器
    changed = {}
    for name in GPR_NAMES:
        pre = pre_vals.get(name, 0)
        post = post_vals.get(name, 0)
        if pre != post:
            changed[name] = (pre, post)

    # 输出注解
    parts_before = []
    for name in GPR_NAMES:
        if name in changed:
            parts_before.append(f"{name}=0x{changed[name][0]:x}")

    parts_mem = []
    try:
        accesses = vm.getInstMemoryAccess()
        for ma in accesses:
            if ma.type & pyqbdi.MEMORY_WRITE:
                parts_mem.append(f"mem_w=0x{ma.accessAddress:x}")
            elif ma.type & pyqbdi.MEMORY_READ:
                parts_mem.append(f"mem_r=0x{ma.accessAddress:x}")
    except Exception:
        pass

    parts_after = []
    for name, (pre, post) in changed.items():
        parts_after.append(f"{name}=0x{post:x}")

    annot = "; " + " ".join(parts_before + parts_mem)
    if parts_after:
        annot += " -> " + " ".join(parts_after)

    if parts_before or parts_mem or parts_after:
        output.write(line + annot + "\n")
    else:
        output.write(line + "\n")

    return pyqbdi.CONTINUE


def main():
    """示例：对一段函数进行 trace。"""
    vm = pyqbdi.VM()
    state = vm.getGPRState()
    stack = vm.allocateVirtualStack(state, 0x100000)

    vm.recordMemoryAccess(pyqbdi.MEMORY_READ_WRITE)
    vm.addCodeCB(pyqbdi.PREINST, pre_callback, None)
    vm.addCodeCB(pyqbdi.POSTINST, post_callback, None)

    output.write("# QBDI ARM64 Trace (pyqbdi)\n")

    # 在此设置要 trace 的目标函数
    # 示例：vm.addInstrumentedModuleFromAddr(target_addr)
    # vm.call(target_addr, [arg1, arg2, ...])

    print("请在 main() 中设置要 trace 的目标函数。", file=sys.stderr)
    print("参考 QBDI 文档：https://qbdi.quarkslab.com/", file=sys.stderr)


if __name__ == "__main__":
    main()
