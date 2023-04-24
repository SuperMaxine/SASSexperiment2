## ret2syscall复现与分析

### 技术点

- checksec检查可执行文件与内核安全属性
- 使用反汇编工具（IDA pro）查找缓冲区溢出入口和可利用的源码片段
- 使用二进制调试工具（gdb）查看寄存器与内存内容
- 利用gadgets构造栈帧，通过ROP调用系统调用
- 通过ROPgadget工具查找需要的gadgets
- 计算需要覆写的返回地址的偏移
- payload构造

### 分析

首先通过checksec检查可执行文件的保护机制

![image-20230419182517185](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304191825229.png)

能够得知以下信息：

- 可执行文件为是一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“堆栈金丝雀（stack canary）”技术。
- 开启了“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230419182748810](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304191827832.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，但是没有在程序中查找到`/bin/sh`字符串或`system()`函数等易于利用的工具；检查其内存权限属性，也没有找到额外的可执行内存段（如下图）。

![image-20230419183214617](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304191832640.png)

没有可以利用的代码也无法自己输入shellcode来获得shell，因此考虑使用ROP(Return Oriented Programming)方法，利用程序中已有的以`ret`结尾的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而利用`ret`控制子程序返回栈上原主程序地址的特性，达到连续执行多个gadgets控制程序的执行流程。

希望能够构造出系统调用如下：

```
execve("/bin/sh",NULL,NULL)
```

在汇编视角，则需要满足以下寄存器条件并发起系统中断

- eax = 0xb（`execve`的系统调用号）
- ebx = addr('/bin/sh')
- ecx = 0
- edx = 0

当构造好所需寄存器的值后，跳转到任意一个`int 0x80`地址发起系统中断即可实现一次`execve`系统调用。

为了构造寄存器的值，需要利用程序中已有的，以`ret`结尾的程序片段，实现多个片段间的连续跳转和利用，这种程序片段被称为gadgets。通过ROPgadget工具查找需要的gadgets：

![image-20230423110738249](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231107283.png)

控制eax的gadget采用`0x080bb196`位置的`pop eax; ret`。

![image-20230423111106472](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231111498.png)

控制ebx、ecx和edx采用`0x0806eb90 `位置的`pop edx ; pop ecx ; pop ebx ; ret`。

![image-20230423111406420](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231114438.png)

字符串“/bin/sh”程序中仅有一处，即`0x080be408`地址处。

![image-20230423111620018](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231116039.png)

系统中断`int 0x80`在程序中也仅有溢出，即`0x08049421`地址处。

因此构思获得shell的攻击流程如下：

1. 通过`gets()`构造缓冲区溢出攻击，劫持控制流。

2. 覆盖`main()`函数的返回地址为控制eax的gadget地址

3. 在栈中后续内容继续填充希望`pop`进eax寄存器的内容`0xb`

4. 在栈中后续内容（控制eax的gadget的ret地址）继续填充为控制ebx、ecx和edx寄存器的gadget地址

5. 在栈中后续内容继续填充希望`pop`进ebx、ecx、edx寄存器的内容`0`、`0`和字符串“/bin/sh”的地址`0x080be408`

6. 在栈中后续内容（控制ebx、ecx、edx的gadget的ret地址）继续填充为`int 0x80`的地址

   当`main()`函数执行完毕退出时，eip指针返回到第一个gadget的地址并依次执行后续gadget，从而依次满足寄存器内容并最终发起系统中断从而调用`execve`弹出一个shell供攻击者使用

### 攻击复现

接下来实现攻击，同上一两题，要先确定`main()`函数返回地址。

![image-20230423115452588](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231154606.png)

![image-20230423115621344](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231156384.png)

使用与上一题一样的步骤，在`call _gets`的地址`0x08048E96`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffcf20`，其存放的内容即字符串`s`的地址为`0xffffcf3c`；基址指针寄存器ebp的地址为`0xffffcfab`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcfab-0xffffcf3c=0x6c`。此时内存结构如下图所示：

![image-20230423120021465](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231200493.png)

根据上述思路编写payload，构造内存结果如下：

![image-20230423165859531](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231658591.png)

最后的payload如下：

```python
from pwn import *

sh = process('./ret2syscall')
pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
sh.sendline(b'A' * (0x6c+4) + p32(pop_eax_ret) + p32(0xb) + p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(binsh) + p32(int_0x80))
sh.interactive()
```

运行payload脚本，可以成功得到shell。

![image-20230423114713741](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231147764.png)