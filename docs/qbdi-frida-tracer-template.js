// Frida-QBDI Tracer Template for trace-ui
//
// 使用 Frida + QBDI 生成 trace-ui 兼容的 ARM64 trace 日志。
//
// 前置条件：
//   1. 目标设备安装 QBDI 动态库（libQBDI.so / libQBDI.dylib）
//   2. frida-qbdi.js 放在同目录或修改下方 import 路径
//
// 用法：
//   frida -U -f com.example.app -l qbdi-frida-tracer-template.js --no-pause
//
// 输出格式（trace-ui 标准）：
//   0xADDR module+0xOFF: disasm; reg=val ... mem_r=addr/mem_w=addr -> reg=val ...

import {
  VM,
  GPR_NAMES,
  InstPosition,
  VMAction,
  AnalysisType,
  MemoryAccessType,
  CallbackPriority,
} from "./frida-qbdi.js";

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  配置区 — 修改这里来适配你的目标
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const TARGET_MODULE = "libnative.so";
const TARGET_FUNC = null; // 函数导出名，如 "Java_com_example_encrypt"；null 则 trace 整个模块
const MAX_INSN = 500000; // 最大记录指令数，防止卡死
const OUTPUT_FILE = null; // 输出到文件路径（null = 使用 console.log / send）

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const GPR_NAMES_LOWER = GPR_NAMES.map((n) => n.toLowerCase());

let gprPre = null;
let lineCount = 0;

function emit(line) {
  if (OUTPUT_FILE) {
    traceFile.write(line + "\n");
  } else {
    send({ type: "trace", payload: line });
  }
}

let traceFile = null;
if (OUTPUT_FILE) {
  traceFile = new File(OUTPUT_FILE, "w");
}

function formatHex(val) {
  if (
    typeof val === "object" &&
    val !== null &&
    typeof val.toString === "function"
  ) {
    return "0x" + val.toString(16);
  }
  return "0x" + val.toString(16);
}

function startTrace(baseAddr) {
  const vm = new VM();
  const state = vm.getGPRState();
  vm.allocateVirtualStack(state, 0x100000);

  vm.recordMemoryAccess(MemoryAccessType.MEMORY_READ_WRITE);

  // PRE 回调：保存执行前寄存器
  const preCB = vm.newInstCallback(function (_vm, gpr, _fpr, _data) {
    gprPre = {};
    for (let i = 0; i < GPR_NAMES.length; i++) {
      gprPre[i] = gpr.getRegister(i);
    }
    return VMAction.CONTINUE;
  });

  // POST 回调：输出 trace 行
  const postCB = vm.newInstCallback(function (_vm, gpr, _fpr, _data) {
    if (lineCount >= MAX_INSN) return VMAction.BREAK_TO_VM;

    const inst = _vm.getInstAnalysis(
      AnalysisType.ANALYSIS_INSTRUCTION |
        AnalysisType.ANALYSIS_DISASSEMBLY |
        AnalysisType.ANALYSIS_SYMBOL,
    );
    if (!inst) return VMAction.CONTINUE;

    const addr = inst.address;
    const disasm = inst.disassembly || "???";

    // 地址 + 模块偏移
    let prefix;
    if (inst.moduleName) {
      const modBase = Module.findBaseAddress(inst.moduleName);
      if (modBase) {
        const off = addr.sub(modBase);
        prefix =
          formatHex(addr) +
          " " +
          inst.moduleName +
          "+0x" +
          off.toString(16) +
          ": " +
          disasm;
      } else {
        prefix =
          formatHex(addr) +
          " " +
          inst.moduleName +
          "+0x" +
          (inst.symbolOffset || 0).toString(16) +
          ": " +
          disasm;
      }
    } else {
      prefix = formatHex(addr) + ": " + disasm;
    }

    // 执行前后寄存器
    const changed = [];
    const preParts = [];

    for (let i = 0; i < GPR_NAMES_LOWER.length; i++) {
      const pre = gprPre ? gprPre[i] : null;
      const post = gpr.getRegister(i);
      if (pre !== null && !pre.equals(post)) {
        preParts.push(GPR_NAMES_LOWER[i] + "=" + formatHex(pre));
        changed.push({ name: GPR_NAMES_LOWER[i], val: post });
      }
    }

    // 内存访问
    const memParts = [];
    try {
      const accesses = _vm.getInstMemoryAccess();
      if (accesses) {
        for (let j = 0; j < accesses.length; j++) {
          const ma = accesses[j];
          if (ma.type & MemoryAccessType.MEMORY_WRITE) {
            memParts.push("mem_w=" + formatHex(ma.accessAddress));
          } else if (ma.type & MemoryAccessType.MEMORY_READ) {
            memParts.push("mem_r=" + formatHex(ma.accessAddress));
          }
        }
      }
    } catch (_) {
      /* no memory access */
    }

    // 组装 trace 行
    let line = prefix;
    const beforeParts = preParts.concat(memParts);
    if (beforeParts.length > 0 || changed.length > 0) {
      line += "; " + beforeParts.join(" ");
      if (changed.length > 0) {
        line +=
          " -> " +
          changed.map((c) => c.name + "=" + formatHex(c.val)).join(" ");
      }
    }

    emit(line);
    lineCount++;
    return VMAction.CONTINUE;
  });

  vm.addCodeCB(
    InstPosition.PREINST,
    preCB,
    null,
    CallbackPriority.PRIORITY_DEFAULT,
  );
  vm.addCodeCB(
    InstPosition.POSTINST,
    postCB,
    null,
    CallbackPriority.PRIORITY_DEFAULT,
  );

  if (TARGET_FUNC) {
    const funcAddr = Module.findExportByName(TARGET_MODULE, TARGET_FUNC);
    if (!funcAddr) {
      console.error(
        "[QBDI] Cannot find export: " + TARGET_FUNC + " in " + TARGET_MODULE,
      );
      return null;
    }
    vm.addInstrumentedModuleFromAddr(funcAddr);
    return { vm, funcAddr };
  } else {
    vm.addInstrumentedModule(TARGET_MODULE);
    return { vm, funcAddr: baseAddr };
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  方式 1：Hook 目标函数入口，在 QBDI 中执行
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

function hookAndTrace() {
  const mod = Process.findModuleByName(TARGET_MODULE);
  if (!mod) {
    console.log("[QBDI] Module not loaded yet, waiting...");
    const interval = setInterval(function () {
      if (Process.findModuleByName(TARGET_MODULE)) {
        clearInterval(interval);
        hookAndTrace();
      }
    }, 100);
    return;
  }

  console.log("[QBDI] Found " + TARGET_MODULE + " at " + mod.base);
  emit("# QBDI ARM64 Trace (Frida)");
  emit("# module " + TARGET_MODULE + " " + mod.base + " " + mod.size);

  if (TARGET_FUNC) {
    const funcAddr = Module.findExportByName(TARGET_MODULE, TARGET_FUNC);
    if (!funcAddr) {
      console.error("[QBDI] Export not found: " + TARGET_FUNC);
      return;
    }

    Interceptor.attach(funcAddr, {
      onEnter: function (args) {
        console.log(
          "[QBDI] Intercepted " + TARGET_FUNC + ", starting trace...",
        );
        lineCount = 0;

        const result = startTrace(mod.base);
        if (!result) return;
        const { vm, funcAddr: fAddr } = result;

        const state = vm.getGPRState();
        for (let i = 0; i < 8 && i < args.length; i++) {
          state.setRegister("X" + i, args[i]);
        }
        state.synchronizeContext(this.context, 0);

        const retval = vm.call(fAddr, []);
        console.log(
          "[QBDI] Trace done. " + lineCount + " instructions recorded.",
        );

        this._qbdiRetval = retval;
      },
      onLeave: function (retval) {
        if (this._qbdiRetval !== undefined) {
          retval.replace(this._qbdiRetval);
        }
      },
    });

    console.log("[QBDI] Hook installed on " + TARGET_FUNC);
  } else {
    console.log(
      "[QBDI] No TARGET_FUNC specified. Set TARGET_FUNC and hook the desired entry point.",
    );
    console.log(
      "[QBDI] Example: Interceptor.attach(ptr('0x...'), { onEnter: ... })",
    );
  }
}

hookAndTrace();
