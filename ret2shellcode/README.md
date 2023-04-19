## ret2shellcode复现与分析

### 技术点

- checksec检查可执行文件与内核安全属性
- 使用反汇编工具查找可利用的源码片段
- 使用二进制调试工具查看寄存器与内存内容
- 计算需要覆写的返回地址的偏移
- payload构造

### 分析

首先通过checksec检查可执行文件的保护机制

![image-20230418171409400](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304181715199.png)

能够得知以下信息：

- 可执行文件为是一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“堆栈金丝雀（stack canary）”技术。
- 没有开启“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230418172044986](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304181720007.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，但是没有在程序中查找到`/bin/sh`字符串或`system()`函数等易于利用的工具。进一步分析程序，发现程序将输入的字符串`s`拷贝到`buf2`处，考虑`buf2`是否有一些利于利用的特殊性质。

![image-20230418172514969](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304181725995.png)

经过查找发现`buf2`在BSS段`0x0804A080`中，继续检查该内存位置的权限属性。

![image-20230418192259001](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304181922049.png)

对`main()`函数下断点，通过vmmap检查发现`0x0804A000`-`0x0804B000`具有可读可写可执行权限。那么通过`gets()`输入的内容在被拷贝到`buf2`后也可执行。

因此构思获得shell的攻击流程如下：

1. 构造shellcode
2. 通过`gets()`输入shellcode并构造缓冲区溢出攻击，劫持控制流。
3. 覆盖`main()`函数的返回地址为`buf2`的地址。
4. 当`main()`函数执行完毕退出时，eip指针返回到`buf2`中的shellcode继续执行，从而弹出一个shell供攻击者使用。

### 攻击复现

接下来实现攻击，同上一题，要先确定`main()`函数返回地址。

![image-20230418205135752](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304182051767.png)

![image-20230418205656888](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304182056925.png)

使用与上一题一样的步骤，在`call _gets`的地址`0x08048593`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffcee0`，其存放的内容即字符串`s`的地址为`0xffffcefc`；基址指针寄存器ebp的地址为`0xffffcf68`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcf68-0xffffcefc=0x6c`。此时内存结构如下图所示：

![image-20230419120251020](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304191202077.png)

接下来编写的payload要做的就是通过`gets()`函数在`s`字符串地址开始写入shellcode，并填充任意数据直到0x6c长度，覆盖ebp（4个字节），最终改写`main()`函数的返回地址为`buf2`的地址`0x0804A080`。如下图所示：

![image-20230419120525228](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304191205260.png)

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