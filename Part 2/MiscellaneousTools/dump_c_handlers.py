import pefile
import struct
from capstone import *
import sys


def disassemble_function(data, func_offset):
    offset = 0
    while True:
        # Stop when we hit two int3s
        if data[func_offset+offset:func_offset+offset+2] == b"\xCC\xCC":
            break
        offset += 1
    
    function_code = data[func_offset:func_offset+offset]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(function_code, func_offset):
        print("\t\t\t%s %s" %(i.mnemonic, i.op_str))
        if i.mnemonic == "ret":
            break


def main():
    if len(sys.argv) < 2:
        raise Exception(f"Usage: scan_c_handlers.py [target binary] [__C_specific_handler offset]")

    target_binary = sys.argv[1]
    # Function offset of __C_specific_handler.
    # Get this from IDA Pro or any PDB parser.
    cspecifichandler_offset = int(sys.argv[2], 16)

    pe = pefile.PE(target_binary)
    data = pe.get_memory_mapped_image()
    for runtime_function in pe.DIRECTORY_ENTRY_EXCEPTION:
        # First, enumerate entries with an exception handler.
        if hasattr(runtime_function, "unwindinfo") and \
        runtime_function.unwindinfo is not None and \
        runtime_function.unwindinfo.UNW_FLAG_EHANDLER and \
        runtime_function.unwindinfo.ExceptionHandler == cspecifichandler_offset:
            

            unwind_info_size = runtime_function.unwindinfo.sizeof()
            scope_table_offset = runtime_function.struct.UnwindData + unwind_info_size
            scope_table_count = int.from_bytes(data[scope_table_offset:scope_table_offset+4], "little")

            # Print the runtime function and unwind info structure.
            print("\n".join(runtime_function.struct.dump()))
            print("\t[UNWIND_INFO]", end="\n\t")
            print("\n\t".join(runtime_function.unwindinfo.dump()[1:]))
            print("\t\t[SCOPE_TABLE]")

            # Enumerate it.
            entries_offset = scope_table_offset + 4
            scope_entry_size = 4 * 4  # 4 DWORDs, so 4*4
            for i in range(0, scope_table_count):
                entry_offset = entries_offset + (i*scope_entry_size)
                entry_data = data[entry_offset:entry_offset+scope_entry_size]
                begin_address, end_address, handler_address, jump_target = struct.unpack("IIII", entry_data)
                
                print(f"\t\tScope {i}")
                print(f"\t\t{'BeginAddress:'.ljust(30)} {hex(begin_address)}")
                print(f"\t\t{'EndAddress:'.ljust(30)} {hex(end_address)}")
                print(f"\t\t{'HandlerAddress:'.ljust(30)} {hex(handler_address)}")
                if handler_address != 0x1:
                    disassemble_function(data, handler_address)
                print(f"\t\t{'JumpTarget:'.ljust(30)} {hex(jump_target)}")
                if jump_target:
                    disassemble_function(data, jump_target)


if __name__ == "__main__":
    main()
