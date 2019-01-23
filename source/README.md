# kn0ck's blog

## 简介
该仓库为kn0ck战队blog。其中dev分支为开发分支，仅允许kn0ck队内成员修改，发表文章。

## 使用

### 初始化

1. 首先安装node环境。下载地址如下

> http://nodejs.cn/download/

安装Node.js和配置好Node.js环境，打开cmd命令行，成功界面如下

![20190123154822079980990.png](https://img.5am3.com/20190123154822079980990.png)

2. 安装hexo

```
npm install hexo -g
```

输入`hexo -v`，检查hexo是否安装成功 

3. 安装Git和配置好Git环境，具体请百度。

4. Github账户注册，注册完成后，将账号发送给 @5am3，让其拉入项目。

5. 本地clone仓库：

```
git clone -b dev https://github.com/KCTF/kctf.github.io.git
```

6. 本地配置git SSH-key

具体不做介绍，请自行百度。


**至此，基本初始化以及完成。**

### 上传文章

未避免产生冲突，建议大家采取以下方式。

1. 将文章在其他目录写好。（md格式）
2. 然后进入blog目录，进行
```
git pull origin dev:dev
```
3. 运行
```
hexo new "文章标题"
```
4. 将原本写好的文章copy过来。
5. 修改备注信息
6. 部署文章
```
hexo d -g
```
