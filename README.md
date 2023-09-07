<!--
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-08-06 21:50:58
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2023-08-18 15:37:34
 * @FilePath: \SSL-TEST\README.md
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
-->
## 运行

- 服务端
```shell
./server 9112 cert/ca.crt cert/signcert.crt cert/signkey.key cert/enccert.crt cert/enckey.key
```

- 客户端
```shell
./client 127.0.0.1 9112 cert/ca.crt cert/signcert.crt cert/signkey.key cert/enccert.crt cert/enckey.key
```
