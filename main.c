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

void my_err(char *msg, ...)
{

    va_list argp;

    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
}

void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "-r 服务端ip地址\n");
    fprintf(stderr, "-p 服务端端口[1-65535]\n");
    fprintf(stderr, "-e 使用ECDHE-SM2-WITH-SM4-SM3套件\n");
    fprintf(stderr, "-c 最大并发SSL连接目标数,默认值10000\n");
    fprintf(stderr, "-w 测试完成后等待多少秒自动关闭程序,默认值10秒\n");
    fprintf(stderr, "-h 使用帮助\n");
    exit(1);
}

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
    int sockfd, serverport;
    char serverip[16] = {0}; /* server ip string */
    int ret;
    int i, count = 10000, num;
    int t = 10;
    int option, usedhe = 0;

    struct sockaddr_in dest, local;

    // 变量定义
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    const char *sign_key_file = "cert/signkey.key";
    const char *sign_cert_file = "cert/signcert.crt";
    const char *enc_key_file = "cert/enckey.key";
    const char *enc_cert_file = "cert/enccert.crt";

    /* Check command line options */
    while ((option = getopt(argc, argv, "r:p:ec:w:h")) > 0)
    {
        switch (option)
        {
        case 'r':
            strncpy(serverip, optarg, 15);
            break;
        case 'p':
            serverport = atoi(optarg);
            break;
        case 'e':
            usedhe = 1;
            break;
        case 'c':
            count = atoi(optarg);
            break;
        case 'w':
            t = atoi(optarg);
            break;
        case 'h':
            usage();
            break;
        default:
            my_err("Unknown option %c\n", option);
            usage();
        }
    }
    argv += optind;
    argc -= optind;

    if (argc > 0)
    {
        my_err("Too many options!\n");
        usage();
    }

    if (*serverip == '\0')
    {
        my_err("服务端ip地址错误!\n");
        usage();
    }
    else if (serverport <= 0 || serverport > 65535)
    {
        my_err("服务端port错错误[1-65535]!\n");
        usage();
    }
    else if (count < 0)
    {
        my_err("最大并发SSL连接数设置错误[>0]!\n");
        usage();
    }
    else if (t < 0)
    {
        my_err("等待关闭时间错误[>0]!\n");
        usage();
    }

    printf("Test param -> 服务端ip: %s, 服务端port: %d, 是否使用ECDHE: %d, 目标最大SSL连接数: %d, 等待关闭时间: %d秒\n", serverip, serverport, usedhe, count, t);

    // 双证书相关client的各种定义
    meth = NTLS_client_method();
    // 生成上下文
    ctx = SSL_CTX_new(meth);
    // 允许使用国密双证书功能
    SSL_CTX_enable_ntls(ctx);

    // 设置算法套件为ECC-SM2-WITH-SM4-SM3或者ECDHE-SM2-WITH-SM4-SM3
    // 这一步并不强制编写，默认ECC-SM2-WITH-SM4-SM3优先
    if (usedhe)
    {
        if (SSL_CTX_set_cipher_list(ctx, "ECDHE-SM2-WITH-SM4-SM3") <= 0)
            exit(errno);
        // 加载签名证书，加密证书，仅ECDHE-SM2-WITH-SM4-SM3套件需要这一步,
        // 该部分流程用...begin...和...end...注明
        //  ...begin...
        if (!SSL_CTX_use_sign_PrivateKey_file(ctx, sign_key_file,
                                              SSL_FILETYPE_PEM))
            goto exit;

        if (!SSL_CTX_use_sign_certificate_file(ctx, sign_cert_file,
                                               SSL_FILETYPE_PEM))
            goto exit;

        if (!SSL_CTX_use_enc_PrivateKey_file(ctx, enc_key_file,
                                             SSL_FILETYPE_PEM))
            goto exit;

        if (!SSL_CTX_use_enc_certificate_file(ctx, enc_cert_file,
                                              SSL_FILETYPE_PEM))
            goto exit;
        // ...end...
    }
    else
    {
        if (SSL_CTX_set_cipher_list(ctx, "ECC-SM2-WITH-SM4-SM3") <= 0)
            goto exit;
    }

    num = 0;
    for (i = 1; i <= count; i++)
    {
        /* code */
        /* 创建一个 socket 用于 tcp 通信 */
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            perror("Socket");
            break;
        }
        /* 绑定本地ip */
        // memset(&local, 0, sizeof(local));
        // local.sin_family = AF_INET;
        // // local.sin_addr.s_addr = htonl(INADDR_ANY);
        // if (i % 2 == 0)
        // {
        //     local.sin_addr.s_addr = inet_addr("10.123.11.237");
        // }
        // else
        // {
        //     local.sin_addr.s_addr = inet_addr("10.123.11.236");
        // }
        // local.sin_port = htons(0); // 自动分配端口
        // if (bind(sockfd, (struct sockaddr *)&local, sizeof(local)) < 0)
        // {
        //     perror("bind()");
        //     break;
        // }

        /* 初始化服务器端（对方）的地址和端口信息 */
        bzero(&dest, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(serverport);
        if (inet_aton(serverip, (struct in_addr *)&dest.sin_addr.s_addr) == 0)
        {
            perror(serverip);
            break;
        }
        // printf("address created\n");
        /* 连接服务器 */
        if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0)
        {
            perror("Connect ");
            break;
        }

        /* 基于 ctx 产生一个新的 SSL */
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        /* 建立 SSL 连接 */
        if (SSL_connect(ssl) == -1)
        {
            ERR_print_errors_fp(stderr);
            break;
        }
        num++;
        if (i % 1000 == 0)
        {
            sleep(1); // 暂停 1 秒
            printf("already create %d ssl connection\n", num);
        }
    }
    printf("Max concurrent ssl connection: %d\n", num);
    printf("waite for %d second to close\n", t);
    sleep(t);
    return 0;

finish:
    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
exit:
    SSL_CTX_free(ctx);
    return 0;
err:
    return 1;
}
