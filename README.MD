# QQNTFileVerifyPatch - DLLHijackMethod
更方便的过文件检测 </br>
将DLL重名为dbghelp.dll 丢到QQ.exe同目录下重启NTQQ食用 </br>

# 原理
和修补PE文件的原理类似,这里用了伪装为dbghelp.dll劫持QQ的方式(其实还可以劫持version.dll的) </br>
因为DLL被加载的时候特征码不一定扫得到(不知道是我的Sig扫描器太烂了还是什么玄学问题),所以Hook CreateFileW当lpFileName含有launcher.json准备进行喜闻乐见的校验环节的时候就扫描特征码Hook校验函数 </br>