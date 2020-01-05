邪王真眼 Jyaoushingan
===========================
## 关于Jyaoushingan
Jyaoushingan日文的罗马音中文翻译就是邪王真眼。名字来源于《中二病也要谈恋爱》中女主角给自己右眼起的名字。
![Jyaoushingan](https://github.com/xuwuorg/Jyaoushingan/blob/master/img/RfaX7cW.gif "Jyaoushingan")

## 关于这是干嘛的
XJyaoushingan类是用来对Windows PE文件进行解析的一个工具类。简单来说就是外面众多PE工具的一份开源代码。不过我使用了C++将逻辑封装成了一个类方便操作。

目前来说是只支持了X86的文件解析和内存解析。文件解析使用的是文件内存映射方式。

使用方式很简单你只需要包含头文件，然后申明一个变量最后在open即可：
	
    #include "XJyaoushingan.h"
    ......
    XJyaoushingan pec;
    
    //对文件解析，需要传递一个文件路径
    //pec.set_file_path(file_path);
    //对模块内存解析，给个句柄或者直接一个地址就行。
    pec.set_memory_buf((LPVOID)GetModuleHandle(NULL));
    pec.open();    
	
    //至于如何获取PE里面的信息，你只需要get_一下就能获取到你想要的信息。get_可以在XJyaoushingan.h看到详细的信息这里就不多写了。
    prc.get_xxxx();
	
## 编译
我自己使用的开发环境为 vs2019 Community。relsease x86，vs2017_xp(v141_xp)。

不过你无法直接编译成功，因为我并没有开放xwu3.lib和xwu3.dll以及缺少了XString的字符串操作类。不过问题不大，XString类完全是围绕着std::wstring来进行二次封装的。所以有关XString的所有操作都可以直接替换为std::wstring。这里你们就自己手动替换算了。

除了XString字符串类的坑以外并没有其他坑了。

## 目前可以获取到的功能
MZ
PE
节信息
导入表
导出表
重定位表
资源表

常用的估计就上面这些，还缺少两个分两次更新吧。
延迟加载导入表
线程局部变量表

## 关于bug
如果有bug可以直接在github上面提给我。我看到了就会修改。尽可能的保证稳定。