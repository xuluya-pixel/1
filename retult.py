import os
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB

# 1. 基础配置
soPath = 'D:\爬虫核心代码包（新版）\js代码包\阿里全家桶\淘宝APP加密算法\淘宝APP加密\清除花指令\libsgmainso-6.7.260202.so'
loc_db = LocationDB()
container = Container.from_stream(open(soPath, "rb"), loc_db)

def patch_so(file_path, patch_map):
    """
    对so文件进行自动化patch
    :param file_path: 原so文件路径
    :param patch_map: 地址->指令的patch字典
    """
    if not os.path.exists(file_path):
        print(f"错误：找不到文件 {file_path}")
        return

    with open(file_path, 'rb') as f:
        data = bytearray(f.read())

    print(f"--- 开始执行自动化 Patch ---")
    for virt_addr, hex_code in patch_map.items():
        try:
            # 虚拟地址转文件偏移
            file_offset = container.virt2off(virt_addr)
        except:
            # 转换失败则直接使用虚拟地址作为偏移
            file_offset = virt_addr

        if file_offset is not None:
            data[file_offset : file_offset + len(hex_code)] = hex_code
            print(f"[*] 修复地址: {hex(virt_addr)} -> 指令: {hex_code.hex()}")

    # 生成patch后的新文件
    new_file = file_path + '.patched'
    with open(new_file, 'wb') as f:
        f.write(data)
    print(f"--- Patch 完成！新文件: {new_file} ---")

# 2. 构造 Patch 数据
nop_instr = b'\x1f\x20\x03\xd5'  # ARM64 NOP 指令
patches = {}

def add_patch_range(start_nop, end_nop, br_addr, b_instr_hex):
    """
    批量添加NOP指令 + 跳转指令
    :param start_nop: NOP起始地址
    :param end_nop: NOP结束地址
    :param br_addr: 跳转指令地址
    :param b_instr_hex: 跳转指令机器码
    """
    patches[br_addr] = b_instr_hex
    # 按4字节遍历，批量NOP
    for addr in range(start_nop, end_nop, 4):
        patches[addr] = nop_instr

# sub_145F9C
add_patch_range(0x14864C, 0x14867C, 0x14867C, b'\x05\x00\x00\x14')


# 3. 执行Patch
if __name__ == "__main__":
    patch_so(soPath, patches)




