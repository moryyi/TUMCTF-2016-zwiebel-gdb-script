# TUMCTF-2016-zwiebel-gdb-script
A gdb python script on solving zwiebel based on LiveOverflow radare2 script

## Run
- Open zwiebel with gdb
`gdb ./zwiebel -quiet`

- execute script
`source zwiebel-gdb.py`

- press `c` if the following statement shows:
> --Type <RET> for more, q to quit, c to continue without paging--

## Purpose
The original purpose of this repo was to learn how to use r2pipe with python script.
But the latest radare2 and r2pipe doesn't perform currectly on zwiebel challenge, probably on any other challenge program that will execute instructions allocated in heap.
Therefore, I switched to GDB python and followed the normal method to solve this challenge. This is a easy challenge so it won't take too long to understand the method and this script.
Anyway, the way that LiveOverflow chooses to print out the flag is probably what a hacker really want.
:)
