<!--
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-08-06 21:50:58
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2023-11-06 10:28:13
 * @FilePath: \SSL-TEST\README.md
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
-->
## ssl最大并发连接压测

### 1、服务器优化配置
```shell
ulimit -n 655350
sysctl -w net.ipv4.ip_local_port_range="1 65535"
```

### 2、测试执行
```shell
./ssl-test -r 10.123.11.231 -p 22231 -c 100000 -w 2000
```

## sslvpn测试

- 服务端
```shell
./server 9001 cert/ca.crt cert/signcert.crt cert/signkey.key cert/enccert.crt cert/enckey.key
```

- 客户端
```shell
./client 127.0.0.1 9001 cert/ca.crt cert/signcert.crt cert/signkey.key cert/enccert.crt cert/enckey.key
```
