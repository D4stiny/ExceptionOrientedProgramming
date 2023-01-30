# Exception Oriented Programming, Part 2

[This article](https://billdemirkapi.me/abusing-exceptions-for-code-execution-part-2/) explores how attackers can abuse the unwinding process to gain code execution.

## Layout
1. **VulnerableAppPoC** - A vulnerable application that exposes
2. **CollidedUnwindExploit** - Contains a Python proof-of-concept that abuses the stack overflow vulnerability in **VulnerableAppPoC** via collided unwinds to load an arbitrary DLL.
    - **Note:** By default, this exploit uses a WebDav server which requires that the "WebClient" service is running on the target. This can be avoided by using a UNC server instead. I opted for a WebDav server only because it was the simplest to automate.
3. **MiscellaneousTools** - Contains Python scripts used in the blog.
    - `dump_c_handlers.py` - Takes a target binary and the offset to `__C_specific_handler` in that binary. Dumps runtime function, unwind info, and the C-specific scope tables (including disassembly of handler/jump target).

