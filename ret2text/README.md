## ret2text复现与分析

### 技术点

- checksec检查可执行文件与内核安全属性
- 

### 分析

首先通过checksec检查可执行文件的保护机制


![image-20230413204256822](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304132043972.png "checksec检查ret2text结果")

能够得知以下信息：

- 可执行文件为是一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术，在重定位后使可执行文件的某些部分（如全局偏移表（GOT）和程序链接表（PLT））成为只读，可以一定程度上防止重写函数指针和劫持控制流。
- 没有开启“堆栈金丝雀（stack canary）”技术，说明可执行程序易受到堆栈缓冲区溢出的影响。
- 开启了“No-eXecute”保护技术，将一些内存区域（如堆栈）标记为不可执行。
- 没有开启“独立位置可执行（Position Independent Executable）”技术，说明可执行文件运行时都在固定的位置加载。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230417110103303](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304171334489.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，因此查找是否有可以利用的工具函数与字符串。先从字符串找起，使用IDA pro的`Alt+t`功能查找字符串`/bin/sh`，成功找到，确认其在程序中存在：

![image-20230417155342041](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304171553065.png)

![image-20230417155155065](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304171551108.png)

然后通过快捷键`X`，使用xrefs功能查找引用了该字符串的指令位置：

![image-20230417155414574](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304171554595.png)

![image-20230417155930178](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304171559200.png)

可以看到在`secure()`函数第12行，调用了`system()`函数并传入了该字符串。得益于`system()`函数的特殊性质，此处可以直接作为缓冲区溢出的调用点。

![image-20230417222453437](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304172224451.png)

查看对应系统调用的汇编源码，记录其起始位置`0x0804863A`。

因此构思获得shell的攻击流程如下：

1. 通过`gets()`构造缓冲区溢出攻击，劫持控制流。
2. 覆盖`main()`函数的返回地址为`system("/bin/sh")`语句的地址。
3. 当`main()`函数执行完毕退出时，eip指针返回到`system("/bin/sh")`语句的地址继续执行，从而弹出一个shell供攻击者使用。

接下来实现攻击，首先要确定返回地址的存储位置。

由`get(s)`汇编代码得知，`s`在堆栈上的位置是相对esp寄存器计算的，所以需要通过调试确定在`call _gets`时esp的地址。

![image-20230417213824829](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304172138855.png)

![image-20230417214429598](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304172144640.png)

通过在`call _gets`的地址`0x080486AE`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffcf00`，其存放的内容即字符串`s`的地址为`0xffffcf1c`；基址指针寄存器ebp的地址为`0xffffcf88`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcf88-0xffffcf1c=0x6c`。此时内存结构如下图所示：

![image-20230417221227687](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304172212724.png)

接下来编写的payload要做的就是通过`gets()`函数在`s`字符串地址开始写入，覆盖ebp，最终改写`main()`函数的返回地址为上面所记录的`system(\bin\sh)`的地址`0x804863A`。最后的payload如下：

```python
from pwn import *

sh = process('./ret2text')
target = 0x804863a
sh.sendline('A' * (0x6c+4) + p32(target))
sh.interactive()
```

运行payload脚本，可以成功得到shell。

![image-20230417222746252](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304172227266.png)
