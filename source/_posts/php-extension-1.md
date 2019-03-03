---
title: 初探php拓展层面(一)
author: p0desta
comment: true
date: 2019-03-03 21:27:55
tags:
	- php拓展
	- 代码审计
categories:
	- web
---

> 本文首发先知社区，文章链接：https://xz.aliyun.com/t/4214


前段时间想写一个静态代码审计工具,需要对php扩展熟悉一些,那么自己从零开始接触这一块,如果有错误的地方,麻烦师傅们指正。

另外呢网上虽然有一些文章,但是感觉都不是特别细,对于刚入门的我来说有些难以理解,因此详细的记录下自己的学习过程。

<!-- more -->

我在mac环境上折腾了两天gdb,还是没折腾好,无奈选择docker,这里推荐一个

```
https://github.com/hxer/php-debug/blob/master/Dockerfile
```

这个dockerfile的vld和php版本不匹配,需要更换下低版本的vld。

启动命令

```
docker run -i -d --security-opt seccomp=unconfined -v /Users/p0desta/Desktop/code:/home php5-debug
```

<a name="ef5359c9"></a>
#### 编写最简单的php扩展

* 在ext目录下执行命令
```
./ext_skel --extname=p0desta
```

* 然后进入到扩展目录下,编辑config.m4文件
```
16 dnl PHP_ARG_ENABLE(foobar, whether to enable foobar support,
17 dnl Make sure that the comment is aligned:
18 dnl [  --enable-foobar           Enable foobar support])
```

<br />删除第16-18行的注释
* 然后去php_p0desta.h文件,添加函数声明
```
PHP_FUNCTION(confirm_foobar_compiled);
PHP_FUNCTION(p0desta);
```

* 然后到p0desta.c中
```
const zend_function_entry p0desta_functions[] = {
	PHP_FE(p0desta, NULL)
	PHP_FE(confirm_p0desta_compiled,	NULL)		/* For testing, remove later. */
	PHP_FE_END	/* Must be the last line in p0desta_functions[] */
};
```

<br />添加如下`PHP_FE(p0desta, NULL)`
* 然后到最底下编写函数
```
PHP_FUNCTION(p0desta)
{
	php_printf("hello world");
}
```

* 然后在当前目录下执行命令
```
phpize
./configure --enable-p0desta --enable-debug
make
```


然后会在modules文件夹下生存`so`文件,在php.ini中添加拓展

```
extension=p0desta.so
```

![](https://ws2.sinaimg.cn/large/006tKfTcly1g09d4l5yfuj30a0062t8y.jpg#align=left&display=inline&height=218&originHeight=218&originWidth=360&status=done&width=360)

然后就可以调用自写的函数。

<a name="bbb46467"></a>
#### php代码的大致执行流程

开始 -> Scanning,将php代码转换为语言片段(Tokens) -> Parsing,将tokens转化为简单而有意义的表达式 -> Compilation,将表达式编译成opcode -> Execution,顺次执行opcodes,从而实现php脚本的功能。

<a name="b1f6dd04"></a>
#### hook最简单的opcode

关于一些宏的解释参考:`https://github.com/pangudashu/php7-internal/blob/master/7/hook.md`

这里我使用`zend_set_user_opcode_handler`函数来hook `echo`函数

```
zend_set_user_opcode_handler(ZEND_ECHO, ppecho);
```

主要原理是将对应的Zend op的handler函数替换成我们自己定义的来实现HOOK

首先我在扩展.h中定义如下

```c
#define ZEND_OPCODE_HANDLER_ARGS void
PHP_FUNCTION(confirm_foobar_compiled);
int ppecho(ZEND_OPCODE_HANDLER_ARGS);
```

扩展.c中

```
PHP_MINIT_FUNCTION(p_echo)
{
	/* If you have INI entries, uncomment these lines
	REGISTER_INI_ENTRIES();
	*/
	zend_set_user_opcode_handler(ZEND_ECHO, ppecho);
	return SUCCESS;
}

int ppecho(ZEND_OPCODE_HANDLER_ARGS)
{
	php_printf("hook success");
	return ZEND_USER_OPCODE_RETURN;
}
```

如果打算放行继续执行的话`return ZEND_USER_OPCODE_DISPATCH`,如果不继续执行的话`return ZEND_USER_OPCODE_RETURN`

编译完之后看一下效果

![](https://ws2.sinaimg.cn/large/006tKfTcly1g09ov5zdttj30em05kmxm.jpg#align=left&display=inline&height=200&originHeight=200&originWidth=526&status=done&width=526)

<a name="4b35f06d"></a>
#### Webshell简单防御初探

关于一些PHP内核中的定义详情请参考`https://www.kancloud.cn/kancloud/php-internals/42755`

这里我们暂时需要了解的有

* 全局变量
```
EG()、这个宏可以用来访问符号表，函数，资源信息和常量
CG() 用来访问核心全局变量
PG() PHP全局变量。我们知道php.ini会映射一个或者多个PHP全局结构。举几个使用这个宏的例子：PG(register_globals), PG(safe_mode), PG(memory_limit)
FG() 文件全局变量。大多数文件I/O或相关的全局变量的数据流都塞进标准扩展出口结构。
```

* 函数类型
<br />Zend引擎将函数分为以下几个类型
```
#define ZEND_INTERNAL_FUNCTION 1
#define ZEND_USER_FUNCTION 2 
#define ZEND_OVERLOADED_FUNCTION 3
#define ZEND_EVAL_CODE 4
#define ZEND_OVERLOADED_FUNCTION_TEMPORARY 5
```

  * ZEND_USER_FUNCTION （用户函数:用户定义的函数）
```php
<?php 
 
function test(){
}
 
?>
```

  * ZEND_INTERNAL_FUNCTION (内部函数:由扩展、PHP内核、Zend引擎提供的内部函数)
  * 变量函数
```php
$func = 'print_r';
$func('i am print_r function.');
```

  * 匿名函数
* php7的_zend_execute_data
```c
struct _zend_execute_data {
	const zend_op       *opline;           /* executed opline                */
	zend_execute_data   *call;             /* current call                   */
	zval                *return_value;
	zend_function       *func;             /* executed function              */
	zval                 This;             /* this + call_info + num_args    */
	zend_execute_data   *prev_execute_data;
	zend_array          *symbol_table;
#if ZEND_EX_USE_RUN_TIME_CACHE
	void               **run_time_cache;   /* cache op_array->run_time_cache */
#endif
#if ZEND_EX_USE_LITERALS
	zval                *literals;         /* cache op_array->literals       */
#endif
};
```


我们看一下如下代码的opcode

```php
<?php
eval("system('whoami');");
```

![](https://ws3.sinaimg.cn/large/006tKfTcly1g09pr975pmj31ci0s2gpv.jpg#align=left&display=inline&height=432&originHeight=1010&originWidth=1746&status=done&width=746)

我们hook掉`INCLUDE_OR_EVAL`

修改`php_hook_eval.h`增加

```
PHP_FUNCTION(confirm_foobar_compiled);
static int HOOK_INCLUDE_OR_EVAL(ZEND_OPCODE_HANDLER_ARGS);
# define ZEND_OPCODE_HANDLER_ARGS zend_execute_data *execute_data
```

修改`hook_eval.c`增加

```
static int HOOK_INCLUDE_OR_EVAL(ZEND_OPCODE_HANDLER_ARGS)
{
	zend_execute_data *tmp = &execute_data;
	zend_op *opline = execute_data->opline;
	return ZEND_USER_OPCODE_DISPATCH;
}
```

直接在`execute_data`中往下找调用的函数`system`

![](https://ws3.sinaimg.cn/large/006tKfTcly1g0jpqxu5fgj32660fgdjz.jpg#align=left&display=inline&height=147&originHeight=556&originWidth=2814&status=done&width=746)

这个也就是操作数

```
string型变量比较特殊，因为内核在保存String型变量时，不仅保存了字符串的值，还保存了它的长度，所以它有对应的两种宏组合STRVAL和STRLEN，即：Z_STRVAL、Z_STRVAL_P、Z_STRVAL_PP与Z_STRLEN、Z_STRLEN_P、Z_STRLEN_PP。
```

编写`HOOK_INCLUDE_OR_EVAL`如下

```
static int HOOK_INCLUDE_OR_EVAL(ZEND_OPCODE_HANDLER_ARGS)
{
	zend_op *opline = execute_data->opline;
	zval *operands = opline->op1.zv;
	char *cmd = Z_STRVAL_P(operands);
	if(cmd){
			if((strstr(cmd, "system")==NULL)&&(strstr(cmd, "exec")==NULL)&&(strstr(cmd, "shell_exec")==NULL)&&(strstr(cmd, "passthru")==NULL)&&(strstr(cmd, "roc_open")==NULL)){
				return ZEND_USER_OPCODE_DISPATCH;
			}else{
			 return ZEND_USER_OPCODE_RETURN;
			}
	}
	return ZEND_USER_OPCODE_DISPATCH; 
}
```

看下执行流程

![](https://ws2.sinaimg.cn/large/006tKfTcly1g0jtsrsagdj326g0dwwpa.jpg#align=left&display=inline&height=132&originHeight=500&originWidth=2824&status=done&width=746)

当然,只hook掉`ZEND_INCLUDE_OR_EVAL`是很难防御的,比如说

```
<?php
eval('echo `whoami`;');
```

这种就必须再去hook `DO_FCALL`

![](https://ws4.sinaimg.cn/large/006tKfTcly1g0jtv6jfryj31dr0u0tob.jpg#align=left&display=inline&height=450&originHeight=1080&originWidth=1791&status=done&width=746)

为了不影响业务并且去做更好的防御,还需要更深入的研究。

参考:

```
http://drops.xmd5.com/static/drops/web-7333.html
https://www.cnblogs.com/iamstudy/articles/php_code_rasp_1.html
```


