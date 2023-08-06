## 运行

- 服务端
```shell
./server 9001 cert/ca.crt cert/signcert.crt cert/signkey.key cert/enccert.crt cert/enckey.key
```

- 客户端
```shell
./client 127.0.0.1 9001 cert/ca.crt cert/signcert.crt cert/signkey.key cert/enccert.crt cert/enckey.key
```
