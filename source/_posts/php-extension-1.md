---
title: 初探php拓展层面
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


#### 编写最简单的php扩展

- 在ext目录下执行命令
```
./ext_skel --extname=p0desta
```

- 然后进入到扩展目录下,编辑config.m4文件
```
16 dnl PHP_ARG_ENABLE(foobar, whether to enable foobar support,
17 dnl Make sure that the comment is aligned:
18 dnl [  --enable-foobar           Enable foobar support])
```

- 删除第16-18行的注释

- 然后去php_p0desta.h文件,添加函数声明
```
PHP_FUNCTION(confirm_foobar_compiled);
PHP_FUNCTION(p0desta);
```

- 然后到p0desta.c中
```
const zend_function_entry p0desta_functions[] = {
	PHP_FE(p0desta, NULL)
	PHP_FE(confirm_p0desta_compiled,	NULL)		/* For testing, remove later. */
	PHP_FE_END	/* Must be the last line in p0desta_functions[] */
};
```

- 添加如下`PHP_FE(p0desta, NULL)`
- 然后到最底下编写函数
```
PHP_FUNCTION(p0desta)
{
	php_printf("hello world");
}
```

- 然后在当前目录下执行命令
```
phpize
./configure --enable-p0desta --enable-debug
make
```

然后会在modules文件夹下生存`so`文件,在php.ini中添加拓展

```
extension=p0desta.so
```

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153079741-4c7090fd-cd68-4345-b79b-6494ee37879a.png#align=left&display=inline&height=430&originHeight=430&originWidth=720&size=0&status=done&width=720)

然后就可以调用自写的函数。


#### php代码的大致执行流程

开始 -> Scanning,将php代码转换为语言片段(Tokens) -> Parsing,将tokens转化为简单而有意义的表达式 -> Compilation,将表达式编译成opcode -> Execution,顺次执行opcodes,从而实现php脚本的功能。


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

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153079547-3db86644-1931-473b-a9ac-a49e54bad890.png#align=left&display=inline&height=400&originHeight=400&originWidth=1056&size=0&status=done&width=1056)


#### Webshell简单防御初探

关于一些PHP内核中的定义详情请参考`https://www.kancloud.cn/kancloud/php-internals/42755`

这里我们暂时需要了解的有

- 全局变量
```
EG()、这个宏可以用来访问符号表，函数，资源信息和常量
CG() 用来访问核心全局变量
PG() PHP全局变量。我们知道php.ini会映射一个或者多个PHP全局结构。举几个使用这个宏的例子：PG(register_globals), PG(safe_mode), PG(memory_limit)
FG() 文件全局变量。大多数文件I/O或相关的全局变量的数据流都塞进标准扩展出口结构。
```

- 函数类型
Zend引擎将函数分为以下几个类型
```
#define ZEND_INTERNAL_FUNCTION 1
#define ZEND_USER_FUNCTION 2 
#define ZEND_OVERLOADED_FUNCTION 3
#define ZEND_EVAL_CODE 4
#define ZEND_OVERLOADED_FUNCTION_TEMPORARY 5
```

  - ZEND_USER_FUNCTION （用户函数:用户定义的函数）
```php
<?php 
 
function test(){
}
 
?>
```

  - ZEND_INTERNAL_FUNCTION (内部函数:由扩展、PHP内核、Zend引擎提供的内部函数)
  - 变量函数
```php
$func = 'print_r';
$func('i am print_r function.');
```

  - 匿名函数
- php7的_zend_execute_data
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

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153079571-a4ab6121-bf21-4d74-9c35-f37c9ed57a11.png#align=left&display=inline&height=1618&originHeight=1618&originWidth=2736&size=0&status=done&width=2736)

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

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153079797-5582aae3-35f1-47f0-847d-7317e81ff6f2.png#align=left&display=inline&height=568&originHeight=568&originWidth=2878&size=0&status=done&width=2878)

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

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153079566-e711a7e4-2981-44cb-ab38-21fd9eee72e2.png#align=left&display=inline&height=496&originHeight=496&originWidth=2878&size=0&status=done&width=2878)

当然,只hook掉`ZEND_INCLUDE_OR_EVAL`是很难防御的,比如说

```
<?php
eval('echo `whoami`;');
```

这种就必须再去hook `DO_FCALL`

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153079577-f8d0e0e9-633f-479b-907b-9153a770eb8a.png#align=left&display=inline&height=1622&originHeight=1622&originWidth=2680&size=0&status=done&width=2680)

为了不影响业务并且去做更好的防御,还需要更深入的研究。

参考:

```
http://drops.xmd5.com/static/drops/web-7333.html
https://www.cnblogs.com/iamstudy/articles/php_code_rasp_1.html
```



这篇我讲继续学习污点标记以及标记打在何处,学习过程我会通过阅读`http://pecl.php.net/package/taint`的源码来详述实现原理和一些细节。

下一篇讲会对污点跟踪进行分析。


#### 污点标记

这里我们认为所有传入的数据都是不可信的,也就是说所有通过请求发送过来的数据都需要打上标记,被打上标记的数据是会传播的,比如说当进行字符串的拼接等操作在结束后要对新的数据从新标记,因为这个新的字符串仍然是不可信数据,但是经过一些处理函数,比如说`addslashes`这类函数,就可以将标记清除掉。


##### 标记点

首先我们需要知道怎么打标记,将标记打在何处

首先php7和php5的变量结构体是不一样的,因为结构体的不同,标记打在何处也就产生了区别

- php7
```c
typedef union _zend_value {
	zend_long         lval;				/* long value */
	double            dval;				/* double value */
	zend_refcounted  *counted;
	zend_string      *str;
	zend_array       *arr;
	zend_object      *obj;
	zend_resource    *res;
	zend_reference   *ref;
	zend_ast_ref     *ast;
	zval             *zv;
	void             *ptr;
	zend_class_entry *ce;
	zend_function    *func;
	struct {
		uint32_t w1;
		uint32_t w2;
	} ww;
} zend_value;

typedef struct _zend_refcounted_h {
	uint32_t         refcount;			/* reference counter 32-bit */
	union {
		struct {
			ZEND_ENDIAN_LOHI_3(
				zend_uchar    type,
				zend_uchar    flags,    /* used for strings & objects */
				uint16_t      gc_info)  /* keeps GC root number (or 0) and color */
		} v;
		uint32_t type_info;
	} u;
} zend_refcounted_h;
```

- 在taint中,对于php7来说污染标记的原理是利用`zend_uchar flags`变量回收结构中未被使用的标记为去做污染标记,如果随着版本的升级,这个位被使用后,那么就会产生冲突。
- php5
```c
typedef union _zvalue_value {
	long lval;					/* long value */
	double dval;				/* double value */
	struct {
		char *val;
		int len;
	} str;
	HashTable *ht;				/* hash table value */
	zend_object_value obj;
	zend_ast *ast;
} zvalue_value;

struct _zval_struct {
	/* Variable information */
	zvalue_value value;		/* value */
	zend_uint refcount__gc;
	zend_uchar type;	/* active type */
	zend_uchar is_ref__gc;
};
```

- 可以看到这个版本的字段并不多,没有方便我们做标记的位置。
看下taint中是如何实现的吧。

```
Z_STRVAL_PP(ppzval) = erealloc(Z_STRVAL_PP(ppzval), Z_STRLEN_PP(ppzval) + 1 + PHP_TAINT_MAGIC_LENGTH);
PHP_TAINT_MARK(*ppzval, PHP_TAINT_MAGIC_POSSIBLE);
```

看的宏的定义

```
#define PHP_TAINT_MAGIC_NONE     0x00000000
#define PHP_TAINT_MAGIC_POSSIBLE 0x6A8FCE84
#define PHP_TAINT_MAGIC_UNTAINT  0x2C5E7F2D

#define PHP_TAINT_MARK(zv, mark) *((unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1)) = (mark)
#define PHP_TAINT_POSSIBLE(zv) (*(unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1) == PHP_TAINT_MAGIC_POSSIBLE)
#define PHP_TAINT_UNTAINT(zv)  (*(unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1) == PHP_TAINT_MAGIC_UNTAINT)
```

可能这样看不是很直观,直接看图

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153113125-d2313878-e53c-455b-a82c-667b41d2ce6b.png#align=left&display=inline&height=1234&originHeight=1234&originWidth=2282&size=0&status=done&width=2282)

既然这样,那么当想要消除标记的时候直接再将

```
#define PHP_TAINT_MAGIC_NONE     0x00000000
```

打上即可。


##### http请求

上面我们认为所有的请求都是不可信的,再没有经过安全函数时都要打上标记,接下来看下获取http请求参数以及给参数打上标记。

获取http请求参数,看鸟哥的文章`http://www.laruence.com/2008/04/04/17.html`

```
#define TRACK_VARS_POST           0
#define TRACK_VARS_GET            1
#define TRACK_VARS_COOKIE         2
#define TRACK_VARS_SERVER         3
#define TRACK_VARS_ENV            4
#define TRACK_VARS_FILES          5
#define TRACK_VARS_REQUEST        6
```

鸟哥问中提到`根据测试的结果，可以认定PG(http_globals)[TRACK_VARS_GET]是一个hash table;`

我们先利用一下代码获取一下请求参数看一下,这里为了简单分析,直接修改上篇文章HOOK_INCLUDE_OR_EVAL来分析

```
HashTable *ht;
	zval *arr;
	arr = PG(http_globals)[TRACK_VARS_GET];
	ht = HASH_OF(arr);
```

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153113137-d266e5e5-cf6a-4e0f-9ece-9f861d69e788.png#align=left&display=inline&height=944&originHeight=944&originWidth=2862&size=0&status=done&width=2862)

可以看到是可以直接从这个hashtable里面获取到我们的参数的

可以利用相关的宏方便获取的,在zend_hash.h里面可以找到相关的宏

将hashtable中的数据全都遍历出来

```c
static int HOOK_INCLUDE_OR_EVAL(ZEND_OPCODE_HANDLER_ARGS)
{
	ulong num_index;
	char *str_index;
	zval **data;
	HashTable *ht;
	zval *arr;
  char *data;
	char *key;
	arr = PG(http_globals)[TRACK_VARS_GET];
	ht = HASH_OF(arr);

	for (zend_hash_internal_pointer_reset(ht);
			zend_hash_has_more_elements(ht) == SUCCESS;
			zend_hash_move_forward(ht))
	{
		zend_hash_get_current_key(ht, &str_index, &num_index, 0);
		zend_hash_get_current_data(ht, (void**)&data);
		key = Z_STRVAL_PP(data);
		
	} 
	return ZEND_USER_OPCODE_DISPATCH; 
}
```

这几个函数的作用其实命名已经很明确了,但是还是想看一下,拿`zend_hash_get_current_key`来说

我们打个断点`break zend_hash_get_current_key_ex`

我们来看一下

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153113144-0d7921e9-8a8e-4502-8963-54c2fc9892ed.png#align=left&display=inline&height=1106&originHeight=1106&originWidth=2874&size=0&status=done&width=2874)

正如上面所说,跟命名是一样的,`str_index`将返回我们想要得到的key

将其打印出来

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153113153-fc179079-04a0-4db5-825f-865cf07ff90a.png#align=left&display=inline&height=336&originHeight=336&originWidth=920&size=0&status=done&width=920)


##### 打标记

我们重新创建一个扩展,完成基本定义

```c
#define PHP_TAINT_MAGIC_LENGTH   sizeof(unsigned)
#define PHP_TAINT_MAGIC_NONE     0x00000000
#define PHP_TAINT_MAGIC_POSSIBLE 0x6A8FCE84
#define PHP_TAINT_MAGIC_UNTAINT  0x2C5E7F2D
PHP_FUNCTION(confirm_foobar_compiled);
#define ZEND_OPCODE_HANDLER_ARGS zend_execute_data *execute_data
#define PHP_TAINT_MARK(zv, mark) *((unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1)) = (mark)
#define PHP_TAINT_POSSIBLE(zv) (*(unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1) == PHP_TAINT_MAGIC_POSSIBLE)
#define PHP_TAINT_UNTAINT(zv)  (*(unsigned *)(Z_STRVAL_P(zv) + Z_STRLEN_P(zv) + 1) == PHP_TAINT_MAGIC_UNTAINT)
```

我们在请求初始化时,也就是`PHP_RINIT_FUNCTION`里面进行调用

```c
PHP_RINIT_FUNCTION(ptaint)
{
	if(PG(http_globals)[TRACK_VARS_GET] && zend_hash_num_elements(Z_ARRVAL_P(PG(http_globals)[TRACK_VARS_GET]))) {
		php_taint_mark_arr(PG(http_globals)[TRACK_VARS_GET] TSRMLS_CC);
	}
	return SUCCESS;
}
```

然后递归对数组进行标记

```c
static void php_taint_mark_arr(zval *symbol_table TSRMLS_DC)
{
	zval **data;
	HashTable *ht = Z_ARRVAL_P(symbol_table);

	for (zend_hash_internal_pointer_reset(ht);
			zend_hash_has_more_elements(ht) == SUCCESS;
			zend_hash_move_forward(ht))
	{


		if(zend_hash_get_current_data(ht, (void**)&data) == FAILURE)
			continue;

		if(Z_TYPE_PP(data) == IS_ARRAY)
		{
			php_taint_mark_arr(*data TSRMLS_CC);
		}else if(Z_TYPE_PP(data) == IS_STRING){
			Z_STRVAL_PP(data) = erealloc(Z_STRVAL_PP(data), Z_STRLEN_PP(data) + 1 + PHP_TAINT_MAGIC_LENGTH);
			PHP_TAINT_MARK(*data, PHP_TAINT_MAGIC_POSSIBLE);
		}
	} 
}
```

看下效果

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153113228-9d05e619-54a4-4d9d-ac9e-252dedd9c44b.png#align=left&display=inline&height=1618&originHeight=1618&originWidth=2548&size=0&status=done&width=2548)

参考：

```
http://www.laruence.com/2009/04/28/719.html
https://www.jianshu.com/p/c6dea66c54f3
https://www.cnblogs.com/iamstudy/articles/php_code_rasp_2.html
```


上篇写的污点标记,这篇我会分析一下污点传播以及检测攻击点。


#### 思路

这里我暂且认为只要经过类似`mysql_real_escape_string`、`addslashes`、`htmlentities`这类函数,我们都将标记清除,但是如果经过类似`base64_decode`、`strtolower`或者字符串拼接这类经过传递仍然可能存在危害的函数,我们要进行标记传递。

这里有个问题,就是如果开始的时候进行了全局转义,就一定没有了危险嘛,如果某次请求又经过了类似 `stripslashes`这样的函数使引号逃逸出来呢,这里我觉得可以不进行污点清除,将其置为中间态,经过`stripslashes`的时候再恢复污点状态,这样可以减少一部分漏报。

然后思路是在一开始所有的请求变量都打上标记,在一些危险函数,如`eval`、`include`、`file_put_contents`、`unlink`这类函数时进行检测标记,如果仍然存在标记,我们认为它存在攻击点,因此做出警告。


#### 污点传播

这里需要了解的知识点

```c
//操作数类型
#define IS_CONST    (1<<0)  //1:字面量，编译时就可确定且不会改变的值，比如:$a = "hello~"，其中字符串"hello~"就是常量
#define IS_TMP_VAR  (1<<1)  //2:临时变量，比如：$a = "hello~" . time()，其中"hello~" . time()的值类型就是IS_TMP_VAR
#define IS_VAR      (1<<2)  //4:PHP变量是没有显式的在PHP脚本中定义的，不是直接在代码通过$var_name定义的。这个类型最常见的例子是PHP函数的返回值
#define IS_UNUSED   (1<<3)  //8:表示操作数没有用
#define IS_CV       (1<<4)  //16:PHP脚本变量，即脚本里通过$var_name定义的变量，这些变量是编译阶段确定的
```

以及opline里获取到参数，大致思路是，根据HOOK的OP指令的不同，获取op1或者op2，然后根据op1_type或者op2_type分情况抽取参数值：

```
（1）    IS_TMP_VAR
如果op的类型为临时变量，则调用get_zval_ptr_tmp获取参数值。
（2）    IS_VAR
如果是变量类型，则直接从opline->var.ptr里获取
（3）    IS_CV
如果是编译变量参考ZEND_ECHO_SPEC_CV_HANDLER中的处理方式，是直接从EG(active_symbol_table)中寻找。
（4）IS_CONST
如果op类型是常量，则直接获取opline->op1.zv即可。
上述方法都是从PHP源码中选取的，比如一个ZEND_ECHO指令的Handler会有多个，分别处理不同类型的op，这里有：
ZEND_ECHO_SPEC_VAR_HANDLER
ZEND_ECHO_SPEC_TMP_HANDLER
ZEND_ECHO_SPEC_CV_HANDLER
ZEND_ECHO_SPEC_CONST_HANDLER
```

但是这里也有说的不对的地方,可能是版本的原因,比如说`opline->var.ptr`,我们直接这样是获取不到的,但是我们可以参考tmp的实现方式。

具体请看`zend_execute.c`

我们来看下`get_zval_ptr_tmp`是如何实现的

```c
static zend_always_inline zval *_get_zval_ptr_tmp(zend_uint var, const zend_execute_data *execute_data, zend_free_op *should_free TSRMLS_DC)
{
	return should_free->var = &EX_T(var).tmp_var;
}
```

但是这个接口我们并不能直接调用,所以必须重新实现一下

```c
#define PTAINT_T(offset) (*EX_TMP_VAR(execute_data, offset))

static zval *ptaint_get_zval_ptr_tmp(zend_uint var, const zend_execute_data *execute_data, zend_free_op *should_free TSRMLS_DC)
{
	return should_free->var = &PTAINT_T(var).tmp_var;
}

static int hook_include_or_eval(ZEND_OPCODE_HANDLER_ARGS)
{
	zend_op *opline = execute_data->opline;
	zval *op1 = NULL;
	zend_free_op free_op1;
	switch (PTAINT_OP1_TYPE(opline))
	{
		case IS_TMP_VAR:
			op1 = ptaint_get_zval_ptr_tmp(opline->op1.var, execute_data, &free_op1 TSRMLS_CC);
			break;
		default:
			break;
	}
	return ZEND_USER_OPCODE_DISPATCH; 
}
```

看一下效果

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153153499-aecf8b20-d1e9-4f3d-81f0-542d50a57813.png#align=left&display=inline&height=778&originHeight=778&originWidth=2868&size=0&status=done&width=2868)

可以看到这样实现是可以的,那么我们完善代码

```c
static zval *ptaint_get_zval_ptr_tmp(zend_uint var, const zend_execute_data *execute_data, zend_free_op *should_free TSRMLS_DC)
{
	return should_free->var = &PTAINT_T(var).tmp_var;
}
static zval *ptaint_get_zval_ptr_var(zend_uint var, const zend_execute_data *execute_data, zend_free_op *should_free TSRMLS_DC)
{
	zval *ptr = PTAINT_T(var).var.ptr;
	return should_free->var = ptr;
}
static zval **ptaint_get_zval_cv_lookup(zval ***ptr, zend_uint var, int type TSRMLS_DC)
{
	zend_compiled_variable *cv = &CV_DEF_OF(var);

	if (!EG(active_symbol_table) ||
	    zend_hash_quick_find(EG(active_symbol_table), cv->name, cv->name_len+1, cv->hash_value, (void **)ptr)==FAILURE) {
		switch (type) {
			case BP_VAR_R:
			case BP_VAR_UNSET:
				zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
				/* break missing intentionally */
			case BP_VAR_IS:
				return &EG(uninitialized_zval_ptr);
				break;
			case BP_VAR_RW:
				zend_error(E_NOTICE, "Undefined variable: %s", cv->name);
				/* break missing intentionally */
			case BP_VAR_W:
				Z_ADDREF(EG(uninitialized_zval));
				if (!EG(active_symbol_table)) {
					*ptr = (zval**)EX_CV_NUM(EG(current_execute_data), EG(active_op_array)->last_var + var);
					**ptr = &EG(uninitialized_zval);
				} else {
					zend_hash_quick_update(EG(active_symbol_table), cv->name, cv->name_len+1, cv->hash_value, &EG(uninitialized_zval_ptr), sizeof(zval *), (void **)ptr);
				}
				break;
		}
	}
	return *ptr;
}
static zval *ptaint_get_zval_ptr_cv(zend_uint var, int type TSRMLS_DC)
{
	zval ***ptr = EX_CV_NUM(EG(current_execute_data), var);

	if (UNEXPECTED(*ptr == NULL)) {
		return *ptaint_get_zval_cv_lookup(ptr, var, type TSRMLS_CC);
	}
	return **ptr;
}

static int hook_include_or_eval(ZEND_OPCODE_HANDLER_ARGS)
{
	zend_op *opline = execute_data->opline;
	zval *op1 = NULL;
	zend_free_op free_op1;
	switch (PTAINT_OP1_TYPE(opline))
	{
		case IS_TMP_VAR:
			op1 = ptaint_get_zval_ptr_tmp(PTAINT_OP1_GET_VAR(opline), execute_data, &free_op1 TSRMLS_CC);
			break;
		case IS_VAR:
			op1 = ptaint_get_zval_ptr_var(PTAINT_OP1_GET_VAR(opline), execute_data, &free_op1 TSRMLS_CC);
			break;
		case IS_CONST:
			op1 = PTAINT_OP1_GET_ZV(opline);
			break;
		case IS_CV:
			op1 = ptaint_get_zval_ptr_cv(PTAINT_OP1_GET_VAR(opline), 0);

	}
	if(op1 && Z_TYPE_P(op1) == IS_STRING && PHP_TAINT_POSSIBLE(op1))
	{
		if (opline->extended_value == ZEND_EVAL)
		{
				zend_error(E_WARNING, "(eval): Variables are not safely processed into the function");
		}else{
				zend_error(E_WARNING, "(include or require): Variables are not safely processed into the function");
		}
	}
	return ZEND_USER_OPCODE_DISPATCH; 
}
```

至此,hook opcode来检测标记已经完成,但是有一部分函数需要来重新实现检测操作,下面来做解释,首先看一下

```c
typedef struct _zend_internal_function {
	/* Common elements */
	zend_uchar type;
	const char * function_name;
	zend_class_entry *scope;
	zend_uint fn_flags;
	union _zend_function *prototype;
	zend_uint num_args;
	zend_uint required_num_args;
	zend_arg_info *arg_info;
	/* END of common elements */

	void (*handler)(INTERNAL_FUNCTION_PARAMETERS);
	struct _zend_module_entry *module;
} zend_internal_function;
```

Hook内部函数其实和hook opcode的思路大体一致,通过修改handler的指向,指向我们实现的函数,在完成相应操作后继续调用原来的函数实现hook。

这里参考taint的实现,修改handler

```c
static void ptaint_override_func(char *name, uint len, php_func handler, php_func *stash TSRMLS_DC) /* {{{ */ {
	zend_function *func;
	if (zend_hash_find(CG(function_table), name, len, (void **)&func) == SUCCESS) {
		if (stash) {
			*stash = func->internal_function.handler;
		}
		func->internal_function.handler = handler;
	}
}
```

看下效果,handler的地址成功被修改

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153153501-33729b38-9c49-40e5-ae75-387b33f63ccd.png#align=left&display=inline&height=492&originHeight=492&originWidth=2872&size=0&status=done&width=2872)

但是如此的话是有问题的,在进行修改handler的时候需要考虑会不会覆盖掉原来的,因此这里定义了一个新的结构体

```c
static struct ptaint_overridden_fucs /* {{{ */ {
	php_func strval;
	php_func sprintf;
	php_func vsprintf;
	php_func explode;
	php_func implode;
	php_func trim;
	php_func rtrim;
	php_func ltrim;
	php_func strstr;
	php_func str_pad;
	php_func str_replace;
	php_func substr;
	php_func strtolower;
	php_func strtoupper;
} ptaint_origin_funcs;
```

在修改handler处

```c
if (stash) {
			*stash = func->internal_function.handler;
		}
		func->internal_function.handler = handler;
```

这里存储原函数的地址

![](https://cdn.nlark.com/yuque/0/2019/png/228577/1557153153505-acb4804b-d875-48c7-a5f5-c94abced3394.png#align=left&display=inline&height=790&originHeight=790&originWidth=2546&size=0&status=done&width=2546)

然后将原来的handler修改为新函数,然后在新函数中利用上面的指针可以重新调用原来的处理函数

```
PHP_FUNCTION(ptaint_strtoupper)
{
	zval *str;
	int tainted = 0;
	php_func strtoupper;
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &str) == FAILURE) {
		return;
	}
	
	if (IS_STRING == Z_TYPE_P(str) && PHP_TAINT_POSSIBLE(str)) {
		tainted = 1;
	}

	PTAINT_O_FUNC(strtoupper)(INTERNAL_FUNCTION_PARAM_PASSTHRU);
	
	if (tainted && IS_STRING == Z_TYPE_P(return_value) && Z_STRLEN_P(return_value)) {
		Z_STRVAL_P(return_value) = erealloc(Z_STRVAL_P(return_value), Z_STRLEN_P(return_value) + 1 + PHP_TAINT_MAGIC_LENGTH);
		PHP_TAINT_MARK(return_value, PHP_TAINT_MAGIC_POSSIBLE);
	}
}
```

然后在这重新调用原来函数执行,如果原来的字符串有标记的话将返回值也打上标记进行标记传递。

同样的原理,如果多个参数的情况,可以根据情况进行污点的检测,当然,如果想要做的更细的话,那就需要华更多的心思了。

文章到这里就结束了,感谢鸟哥的taint给了学习的机会,在后面一段时间我会去做完我想做的项目,如果有必要,我会把后续的记录整理后发出来,感谢。

参考：

```
https://segmentfault.com/a/1190000014234234
http://www.voidcn.com/article/p-gdecovzj-bpp.html
https://paper.seebug.org/449/
```

