# Ghidra Script to get code of function without NOP and LEA X \[X\]
Both scripts produce a txt file with ordered instruction without NOP and LEA X [X]. 
FunctionSimplifier is more complete: replaces 2-digits hex with ascii characters and tries to adds label from conditional jumps.
Use these scripts for very big functions with lots of jumps and useless instructions.

## Prerequisites
Java 17+

## Installation
1. Clone the repository
2. Open Ghidra's Script Manager and add the directory (Manage Script Directories) where you cloned this repo  

## Instructions
1. Select a function in Ghidra or an instruction that belongs to it
2. Run the desired script
3. The output file will be created on the Desktop with the name of the function.

## Known Issues
- Both scripts don't include in the output file useful unconditional jumps
- Function simplifier often puts conditional jump labels one instruction before the correct one