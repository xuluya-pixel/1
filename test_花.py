import loguru
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
import re

# ===================== 配置路径 =====================
soPath = r"D:\爬虫核心代码包（新版）\js代码包\阿里全家桶\淘宝APP加密算法\淘宝APP加密\清除花指令\libsgmainso-6.7.260202.so"
txtPath = r"D:\爬虫核心代码包（新版）\js代码包\阿里全家桶\淘宝APP加密算法\淘宝APP加密\清除花指令\kernel_config.txt"
# 结果保存路径
savePath = r"D:\爬虫核心代码包（新版）\js代码包\阿里全家桶\淘宝APP加密算法\淘宝APP加密\清除花指令\花指令地址结果.txt"

# ===================== 初始化 Miasm =====================
loc_db = LocationDB()
container = Container.from_stream(open(soPath, "rb"), loc_db)
machine = Machine("aarch64l")
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)


# ===================== 从 txt 读取所有偏移地址 =====================
def read_addresses_from_txt(file_path):
    addresses = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            match = re.search(r"0x[0-9a-fA-F]+", line)
            if match:
                addr_str = match.group()
                addr_int = int(addr_str, 16)
                addresses.append(addr_int)
    return addresses


start_address_list = read_addresses_from_txt(txtPath)

# ===================== 存储结果列表 =====================
result_list = []

# ===================== 开始解析 =====================
print("=" * 60)
print("          花指令 ADR + BR X26 地址结果")
print("=" * 60)

for start_addr in start_address_list:
    asm_cfg = mdis.dis_multiblock(start_addr)
    asm_blocks = list(asm_cfg.blocks)

    adr_addr = None
    br_addr = None

    for block in asm_blocks:
        for instr in block.lines:
            addr = instr.offset
            instr_str = str(instr)

            # 捕获 ADR X26
            if instr.name == "ADR" and "X26" in instr_str:
                adr_addr = addr

            # 捕获 BR X26
            if instr.name == "BR" and "X26" in instr_str:
                br_addr = addr

    # 只要同时找到 ADR 和 BR，就加入结果
    if adr_addr is not None and br_addr is not None:
        adr_hex = f"0x{adr_addr:X}"
        br_hex = f"0x{br_addr:X}"

        print(f"\n📌 ADR 指令 | 地址: {adr_hex}")
        print(f"🚨 BR 指令 | 地址: {br_hex}")

        # 存入列表，用于保存
        result_list.append(adr_hex)
        result_list.append(br_hex)

# ===================== 自动保存到 txt 文件 =====================
with open(savePath, "w", encoding="utf-8") as f:
    f.write("========== 花指令地址（ADR + BR X26）==========\n")
    for addr in result_list:
        f.write(addr + "\n")

# ===================== 完成提示 =====================
print("\n" + "=" * 60)
print(f"✅ 解析完成！共找到 {len(result_list)} 个花指令地址")
print(f"✅ 已自动保存到：{savePath}")
print("=" * 60)
# https://gitee.com/xuluya-pixel/test.git
# git remote add origin ttps://gitee.com/xuluya-pixel/test.git

# git commit -m "清除花指令"

