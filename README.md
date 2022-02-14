# Exception Oriented Programming
Execute just-in-time code by abusing existing memory regions. See the article behind this PoC [here](https://billdemirkapi.me).

## Layout
**Windows** - The Windows proof-of-concept for Exception Oriented Programming that implements both SEH and VEH support.

**macOS** - The macOS proof-of-concept for Exception Oriented Programming with the hardened runtime enabled.

## Windows
#### Build instructions
1. Build the proof-of-concept.
2. Execute **without debugging** (i.e through Command Prompt).
3. Check that the expected result (3) is returned.

## macOS
#### Pre-requisites
1. [Homebrew](https://brew.sh).
2. make
3. codesign

#### Build instructions
1. Create and enter a build directory at the root directory of the project (`mkdir build && cd build`).
2. Configure the project using cmake (`cmake -S ../ -B .`).
3. Build the project (`make`).
4. Use codesign to sign the built binary "ExceptionOrientedProgramming" with the hardened runtime (`codesign --force --options runtime --sign "[your certificate]" ./ExceptionOrientedProgramming`).
5. Execute the "ExceptionOrientedProgramming" and check that the expected result of "7" is returned.
