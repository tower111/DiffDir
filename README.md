## 说明
参考 https://github.com/google/binexport/
https://syscall.eu/blog/2014/06/08/bindiff_export/
给定两个版本的文件，使用ida和bindiff，找出所有二进制文件中有改动的函数

## 运行
- 1、安装bindiff和ida
- 2、修改config.py中ida_path为ida的路径
- 3、input1和output1表示基本文件的路径（旧版本文件），需要修改input
- 4、input2和output2表示新版本文件
- 5、dif_result_log为结果输出目录
- 6、python getsim.py 为输出脚本

## 结果
包含
- 只存在旧固件中的文件
- 只存在新固件中的文件
- 固件中有变动的文件和具体的函数

文件路径，在数据库中的id，地址，函数名，相似度
```
0 id: 65
0 address1: 37972
0 name1: EVP_get_digestbyname
0 address2: 38744
0 name2: EVP_get_digestbyname
0 sim: 0.6600676830890776
```