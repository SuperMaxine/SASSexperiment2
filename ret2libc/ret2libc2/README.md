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

![image-20230424150457551](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241504610.png)

能够得知以下信息：

- 可执行文件为是一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“堆栈金丝雀（stack canary）”技术。
- 开启了“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230424150554617](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241505634.png)

可以看主函数中明显的缓冲区溢出漏洞入口`get(s)`，因此查找是否有可以利用的工具函数与字符串。手动搜索可利用的函数，如libc中的`system()`函数，可通过`Alt+t`查找`_system`：

![image-20230424150725207](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241507224.png)

![image-20230424150741756](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241507811.png)

![image-20230424151022807](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241510823.png)

在`secure()`函数中找到了对`system()`函数的调用，其`system`函数地址`0x08048490`，但传入的字符串"no_shell_QQ"，无法有效利用。但在反汇编程序中搜索字符串，并不能找到字符串`/bin/sh`，需要自己输入，考虑到程序`main()`函数中使用了`gets()`函数，可以进行利用。

![image-20230424151310504](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241513523.png)

经过查找，发现libc中`_gets`在plt表中映射位置`0x08048460`。接着要找一段可读可写的内存作为`_gets`函数的参数，也是`/bin/sh`将要写入的位置，一般选择用来存放程序中未初始化的全局变量的bss段（bss segment）段中的位置。

![image-20230424153940192](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241539255.png)

查看整个bss段，恰好发现`0x0804A080`处存在一个buf2的buffer。因此构思获得shell的攻击流程如下：

1. 通过`gets()`构造缓冲区溢出攻击，劫持控制流。
2. 覆盖`main()`函数的返回地址为`_gets`函数的地址`0x08048460`
3. 后续填入`_system`函数的地址`0x08048490`作为`_gets`函数的返回地址的填充
4. 后续填入buf2的地址，作为`_gets`函数的参数，同时作为`_system`函数的返回地址的填充
5. 后续填入buf2的地址，作为`_system`函数的参数
6. 当`main()`函数执行完毕退出时，eip指针返回到`_gets`的地址并读入后续的虚假返回地址和buf2的地址，读入新的输入`/bin/sh`后，eip指针返回到`_system`函数的地址并读入后续的虚假返回地址和buf2处的字符串，并最终启动一个子进程弹出shell供攻击者使用

### 攻击复现

接下来实现攻击，同上面题目，要先确定`main()`函数返回地址。

![image-20230424154403878](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241544910.png)

![image-20230424154433246](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241544307.png)

使用与上一题一样的步骤，在`call _gets`的地址`0x080486BA`处下断点，可以看到：栈指针寄存器esp此时的地址为`0xffffced0`，其存放的内容即字符串`s`的地址为`0xffffceec`；基址指针寄存器ebp的地址为`0xffffcf58`。通过计算可得，s 相对于 ebp 的偏移为 `0xffffcf58-0xffffceec=0x6c`。此时内存结构如下图所示：

![image-20230424105446557](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241545777.png)

根据上述思路编写payload，构造内存结果如下：

![image-20230424154954650](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241549688.png)

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

![image-20230424155052755](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304241550771.png)