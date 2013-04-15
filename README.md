apache-replace-module
=====================

apache module develop demo，apache 模块开发

对输出结果进行正则替换模块， apache response content replace module，比如域名切换对所有输出url进行替换

apache安装完成之后，使用下面这个命令编译各个模块为so文件

    /usr/local/apache/bin/apxs -c helloworld.c 
    /usr/local/apache/bin/apxs -c urlreplace.c
    /usr/local/apache/bin/apxs -c urlreplacefilter.c
    /usr/local/apache/bin/apxs -c line-editor.c 

编译完之后会在当前目录的.libs下面生存.so的文件，正是apache的so文件。

    helloworld.c 是演示输出一段字符串helloworld的content handler，
    urlreplace.c 是演示读取http.conf配置之后输出的content handler,
    urlreplacefilter.c 是演示读取http.conf配置并将输出小写转为大写的输出过滤器，apache自带的demo做的修改。
    line-editor.c 是对输出内容进行正则替换等内容替换的输出过滤器，已经开源的东西，可以实现我们的共，对输出页面的url域名进行正则替换，项目url为：http://apache.webthing.com/mod_line_edit/。

使用方式如下：在http.conf加入如下配置

    #helloworld.c 对应的配置
    LoadModule helloworld_module mylib/helloworld.so
    <Location /helloworld>
      setHandler helloworld
    </Location>
  
    #urlreplace.c的配置
    srcpath *.china.aaa.com
    descpath *.bbb.com
    LoadModule pathreplace_module mylib/urlreplace.so
    <Location /pathreplace>
      setHandler pathreplace
    </Location>
  
    #urlreplacefilter.c的配置
    LoadModule urlReplace_filter_module mylib/urlreplacefilter.so
    urlReplaceFilter on
  
    #line-editor.c的配置
    srcpath *.china.alibaba.com
    descpath *.1688.com
    LoadModule line_edit_module mylib/line-editor.so
    SetOutputFilter	line-editor
    SetEnv	LineEdit "text/plain;text/css;text/javascript;text/html"
    LERewriteRule CHINA.ALIBABA.COM 1688.com [R]


其中line-editor.c的配置演示如下：比如我们在apache的htdocs下面有个index.htm
    
    <html><body><h1>It works! WWW.CHINA.ALIBABA.COM</h1></body></html>

输出则为：
    
    It works! WWW.1688.com
