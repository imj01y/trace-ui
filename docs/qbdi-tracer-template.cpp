// QBDI Tracer Template for trace-ui
//
// 生成 trace-ui 兼容的 QBDI ARM64 trace 日志。
//
// 输出格式：
//   0xADDR module+0xOFF: disasm; reg=val ... mem_r=addr/mem_w=addr -> reg=val ...
//
// 编译（需已安装 QBDI）：
//   g++ -o tracer qbdi-tracer-template.cpp -lQBDI -std=c++17
//
// 运行：
//   ./tracer > trace.txt

#include <cstdio>
#include <cstring>
#include <vector>

#include <QBDI.h>

static FILE *trace_out = stdout;

static const char *GPR_NAMES_LOWER[] = {
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
    "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "fp",  "lr",  "sp",
    "nzcv", "pc",
};

static QBDI::GPRState gpr_pre;

static QBDI::VMAction preCB(QBDI::VMInstanceRef vm,
                             QBDI::GPRState *gprState,
                             QBDI::FPRState *fprState, void *data) {
    memcpy(&gpr_pre, gprState, sizeof(QBDI::GPRState));
    return QBDI::CONTINUE;
}

static QBDI::VMAction postCB(QBDI::VMInstanceRef vm,
                              QBDI::GPRState *gprState,
                              QBDI::FPRState *fprState, void *data) {
    const QBDI::InstAnalysis *inst = vm->getInstAnalysis(
        QBDI::ANALYSIS_INSTRUCTION | QBDI::ANALYSIS_DISASSEMBLY | QBDI::ANALYSIS_SYMBOL);

    // 地址与模块
    if (inst->moduleName && inst->moduleName[0]) {
        fprintf(trace_out, "0x%lx %s+0x%x: %s",
                (unsigned long)inst->address,
                inst->moduleName,
                inst->symbolOffset,
                inst->disassembly ? inst->disassembly : "???");
    } else {
        fprintf(trace_out, "0x%lx: %s",
                (unsigned long)inst->address,
                inst->disassembly ? inst->disassembly : "???");
    }

    // 执行前的操作数寄存器值
    const QBDI::rword *pre = reinterpret_cast<const QBDI::rword *>(&gpr_pre);
    const QBDI::rword *post = reinterpret_cast<const QBDI::rword *>(gprState);

    // 收集变化的寄存器
    bool has_pre = false;
    bool has_changes = false;

    // 输出执行前的寄存器值（变化的 + 指令涉及的关键寄存器）
    fprintf(trace_out, ";");
    for (int i = 0; i < 34; i++) {
        if (pre[i] != post[i] || (inst->mayLoad && i < 31) || (inst->mayStore && i < 31)) {
            fprintf(trace_out, " %s=0x%lx", GPR_NAMES_LOWER[i], (unsigned long)pre[i]);
            has_pre = true;
        }
    }

    // 内存访问
    std::vector<QBDI::MemoryAccess> accesses = vm->getInstMemoryAccess();
    for (const auto &ma : accesses) {
        if (ma.type & QBDI::MEMORY_WRITE) {
            fprintf(trace_out, " mem_w=0x%lx", (unsigned long)ma.accessAddress);
        } else if (ma.type & QBDI::MEMORY_READ) {
            fprintf(trace_out, " mem_r=0x%lx", (unsigned long)ma.accessAddress);
        }
    }

    // 执行后变化的寄存器值
    for (int i = 0; i < 34; i++) {
        if (pre[i] != post[i]) {
            if (!has_changes) {
                fprintf(trace_out, " ->");
                has_changes = true;
            }
            fprintf(trace_out, " %s=0x%lx", GPR_NAMES_LOWER[i], (unsigned long)post[i]);
        }
    }

    fprintf(trace_out, "\n");
    return QBDI::CONTINUE;
}

// 示例：对 fibonacci 函数进行 trace
QBDI_NOINLINE int fibonacci(int n) {
    if (n <= 2) return 1;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int main(int argc, char **argv) {
    int n = argc >= 2 ? atoi(argv[1]) : 5;
    if (n < 1) n = 1;

    QBDI::VM vm{};
    QBDI::GPRState *state = vm.getGPRState();

    uint8_t *fakestack;
    QBDI::allocateVirtualStack(state, 0x100000, &fakestack);

    vm.recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
    vm.addCodeCB(QBDI::PREINST, preCB, nullptr);
    vm.addCodeCB(QBDI::POSTINST, postCB, nullptr);
    vm.addInstrumentedModuleFromAddr(reinterpret_cast<QBDI::rword>(fibonacci));

    fprintf(trace_out, "# QBDI ARM64 Trace\n");

    QBDI::rword retval;
    vm.call(&retval, reinterpret_cast<QBDI::rword>(fibonacci),
            {static_cast<QBDI::rword>(n)});

    fprintf(stderr, "fibonacci(%d) = %lu\n", n, (unsigned long)retval);

    QBDI::alignedFree(fakestack);
    return 0;
}
