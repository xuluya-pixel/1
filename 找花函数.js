const soName = "libsgmainso-6.7.260202.so";
const scanStart = 0x10000;
const scanEnd   = 0x200000;
const step = 4;

let moduleBase = null;
let hooked = new Set();
let hookCount = 0;

// 只扫描【函数入口级别】的花指令：SUB SP + MRS TPIDR + BR
function scanRealJunkFunctionEntry() {
    try {
        const module = Process.getModuleByName(soName);
        moduleBase = module.base;
        console.log("[*] 模块基址:", moduleBase);
        console.log("[*] 开始扫描【真正的函数入口花指令】...\n");

        for (let off = scanStart; off < scanEnd; off += step) {
            const addr = moduleBase.add(off);
            try {
                // 读取前 6 条指令，判断是否是【函数入口】
                const insns = readMultiInsn(addr, 6);
                if (!insns) continue;

                // 函数入口花指令的【唯一特征】
                let hasSubSP  = false;  // 函数开头：SUB SP, SP, #...
                let hasSTP    = false;  // 保存寄存器：STP X29,X30...
                let hasTPIDR  = false;  // MRS Xxx, TPIDR_EL0
                let hasBR     = false;  // BR Xxx 跳转

                for (let i = 0; i < insns.length; i++) {
                    const mne = insns[i].mnemonic.toLowerCase();
                    const op  = insns[i].opStr.toLowerCase();

                    // 1. 函数入口必备：栈操作
                    if (mne === "sub" && op.includes("sp,")) {
                        hasSubSP = true;
                    }

                    // 2. 函数入口必备：保存栈帧
                    if (mne === "stp" && op.includes("x29, x30")) {
                        hasSTP = true;
                    }

                    // 3. 淘宝特征：读取线程寄存器
                    if (mne === "mrs" && op.includes("tpidr_el0")) {
                        hasTPIDR = true;
                    }

                    // 4. 花指令特征：动态跳转
                    if (mne === "br") {
                        hasBR = true;
                    }
                }

                // ✅ 必须同时满足：栈初始化 + TPIDR + BR = 真正的花指令函数入口
                if (hasSubSP && hasSTP && hasTPIDR && hasBR) {
                    if (!hooked.has(addr.toString())) {
                        hookRealJunkEntry(addr, off);
                    }
                }

            } catch (e) {}
        }

        console.log(`\n[✅ 完成] 精准 Hook 【真正的花指令函数】共: ${hookCount} 个`);
    } catch (e) {
        console.log("[-] 扫描异常:", e);
    }
}

// 读取连续指令
function readMultiInsn(addr, count) {
    let list = [];
    let ptr = addr;
    try {
        for (let i = 0; i < count; i++) {
            const ins = Instruction.parse(ptr);
            list.push(ins);
            ptr = ptr.add(ins.size);
        }
        return list;
    } catch (e) {
        return null;
    }
}

// Hook 真正的函数入口
function hookRealJunkEntry(addr, offset) {
    try {
        Interceptor.attach(addr, {
            onEnter: function() {
                console.log("\n" + "=".repeat(80));
                console.log(`[🔥 命中 花指令函数入口] 偏移: 0x${offset.toString(16)}`);
                console.log(`[LR返回地址] ${this.returnAddress}`);
            },
            onLeave: function(retval) {
                console.log(`[✅ 函数返回] x0 = ${retval}`);
                console.log("=".repeat(80) + "\n");
            }
        });

        hooked.add(addr.toString());
        hookCount++;
        console.log(`[✅ 已Hook] 0x${offset.toString(16)}`);
    } catch (e) {}
}

setTimeout(scanRealJunkFunctionEntry, 2000);