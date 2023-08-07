//
// Created by 刘伟 on 2021/5/8.
//
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_BUF_SIZE 1500

typedef struct
{
    SSL *ssl;   // ssl链接
    int tun_fd; // 虚拟网卡句柄
} CLIENT_TUN_THREAD_PARAM;

static int initTun();

static void *client_tun_thread(void *arg);

void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("无证书信息！\n");
}

int main(int argc, char **argv)
{
    int sockfd, tun_fd, len;
    int ret;
    struct sockaddr_in dest;
    char buffer[MAX_BUF_SIZE + 1];
    CLIENT_TUN_THREAD_PARAM *param = NULL;
    pthread_t clientTunThread;

    // 变量定义
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    const char *sign_key_file = "cert/signkey.key";
    const char *sign_cert_file = "cert/signcert.crt";
    const char *enc_key_file = "cert/enckey.key";
    const char *enc_cert_file = "cert/enccert.crt";

    // 双证书相关client的各种定义
    meth = NTLS_client_method();
    // 生成上下文
    ctx = SSL_CTX_new(meth);
    // 允许使用国密双证书功能
    SSL_CTX_enable_ntls(ctx);

    // 设置算法套件为ECC-SM2-WITH-SM4-SM3或者ECDHE-SM2-WITH-SM4-SM3
    // 这一步并不强制编写，默认ECC-SM2-WITH-SM4-SM3优先
    if (SSL_CTX_set_cipher_list(ctx, "ECC-SM2-WITH-SM4-SM3") <= 0)
        goto err;

    // 加载签名证书，加密证书，仅ECDHE-SM2-WITH-SM4-SM3套件需要这一步,
    // 该部分流程用...begin...和...end...注明
    //  ...begin...
    if (sign_key_file)
    {
        if (!SSL_CTX_use_sign_PrivateKey_file(ctx, sign_key_file,
                                              SSL_FILETYPE_PEM))
            goto err;
    }

    if (sign_cert_file)
    {
        if (!SSL_CTX_use_sign_certificate_file(ctx, sign_cert_file,
                                               SSL_FILETYPE_PEM))
            goto err;
    }

    if (enc_key_file)
    {
        if (!SSL_CTX_use_enc_PrivateKey_file(ctx, enc_key_file,
                                             SSL_FILETYPE_PEM))
            goto err;
    }

    if (enc_cert_file)
    {
        if (!SSL_CTX_use_enc_certificate_file(ctx, enc_cert_file,
                                              SSL_FILETYPE_PEM))
            goto err;
    }
    // ...end...

    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *)&dest.sin_addr.s_addr) == 0)
    {
        perror(argv[1]);
        exit(errno);
    }

    printf("address created\n");

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0)
    {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");

    /* 基于 ctx 产生一个新的 SSL */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1)
    {
        ERR_print_errors_fp(stderr);
        goto exit;
    }
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }

    // 创建tun虚拟网卡
    tun_fd = initTun();
    if (tun_fd <= 0)
    {
        perror("create tun fail");
        goto finish;
    }
    printf("create tun fd: %d\n", tun_fd);

    // 创建client tun读取线程
    param = malloc(sizeof(CLIENT_TUN_THREAD_PARAM));
    if (param == NULL)
    {
        printf("malloc for CLIENT_TUN_THREAD_PARAM fail");
        goto finish;
    }
    param->ssl = ssl;
    param->tun_fd = tun_fd;
    ret = pthread_create(&clientTunThread, NULL, client_tun_thread, param);
    if (ret != 0)
    {
        perror("create client tun thread fail");
        goto finish;
    }

    while (1)
    {
        // 接收对方发过来的消息，最多接收 MAXBUF 个字节
        bzero(buffer, MAX_BUF_SIZE + 1);

        /* 1、接收服务器来的消息 */
        len = SSL_read(ssl, buffer, MAX_BUF_SIZE);
        if (len > 0)
            printf("接收消息成功:'%s'，共%d个字节的数据\n", buffer, len);
        else
        {
            printf("消息接收失败！错误代码是%d，错误信息是'%s'\n", errno, strerror(errno));
            goto finish;
        }

        // TODO 读取到登录成功消息之后再创建虚拟网卡

        /* 2、写入到虚拟网卡 */
        int wlen = write(tun_fd, buffer, len);
        if (wlen < len)
        {
            printf("虚拟网卡写入数据长度小于预期长度, write len: %d, buffer len: %d\n", wlen, len);
        }
    }

finish:
    if (param)
    {
        free(param);
    }
    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
exit:
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;

err:

    return 1;
}

static int initTun()
{
    char dev[32] = {0};
    char *ipv4 = "10.12.9.2";
    char *ipv4_net = "10.12.9.0/24";

    memset(dev, 0, sizeof(dev));
    return tun_create(dev, ipv4, ipv4_net);
}

static void *client_tun_thread(void *arg)
{
    int ret_length;
    CLIENT_TUN_THREAD_PARAM *param = (CLIENT_TUN_THREAD_PARAM *)arg;
    SSL *ssl = param->ssl;
    int tun_fd = param->tun_fd;
    unsigned char buf[MAX_BUF_SIZE + 1];

    // 2、读取虚拟网卡数据
    while (1)
    {
        // 1、读取数据
        ret_length = read(tun_fd, buf, sizeof(buf));
        if (ret_length < 0)
        {
            printf("tun read len < 0\n");
            break;
        }
        // 2、分析报文
        unsigned char src_ip[4];
        unsigned char dst_ip[4];
        memcpy(src_ip, &buf[16], 4);
        memcpy(dst_ip, &buf[20], 4);
        printf("read tun data: %d.%d.%d.%d -> %d.%d.%d.%d (%d)\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
               src_ip[0], src_ip[1], src_ip[2], src_ip[3], ret_length);

        // 3、直接发送到服务端
        int len = SSL_write(ssl, buf, ret_length);
        if (len <= 0)
        {
            printf("消息'%s'发送失败! 错误代码是%d, 错误信息是'%s'\n", buf, errno, strerror(errno));
        }
        bzero(buf, MAX_BUF_SIZE + 1);
    }
}
