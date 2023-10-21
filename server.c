//
// Created by 刘伟 on 2021/5/8.
//

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>

#include "protocol.h"
#include "tun.h"

#define MAX_BUF_LEN 20480

#define MAX_IPV4_STR_LEN 15
#define MAX_IPV6_STR_LEN 45

typedef struct
{
    int tun_fd; // 虚拟网卡句柄
} SERVER_TUN_THREAD_PARAM;

typedef struct
{
    SSL_CTX *ctx;
    SSL *ssl;
    int tun_fd;    // 虚拟网卡句柄
    int sockfd;    // socket句柄
    int handshake; // 是否完成握手
    int dead;      // ssl链接是否失效
} CLIENT_SSL_CACHE;

typedef struct CLIENT_SESSION_S
{
    char ipv4[MAX_IPV4_STR_LEN + 1]; // ipv4地址    10.9.0.1
    char ipv6[MAX_IPV6_STR_LEN + 1];
    CLIENT_SSL_CACHE *clientSslCache;
    struct CLIENT_SESSION_S *next;
} CLIENT_SESSION_T;

static SSL_CTX *createSSLCtx();

static int initTun();

static void *client_ssl_tun_thread(void *arg);

static void *server_tun_thread(void *arg);

static CLIENT_SESSION_T *searchClientSession(char *ipv4);

static int saveClientSession(CLIENT_SESSION_T *clientSession);

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static CLIENT_SESSION_T globalClientSession;

int main(int argc, char **argv)
{
    int ret = 0;
    int sockfd, new_fd, tun_fd;
    struct sockaddr_in server_addr, client_addr;
    int server_port = 9112;
    socklen_t len;

    SSL_CTX *ctx = NULL;

    if (argc > 2)
    {
        server_port = atoi(argv[1]);
        if (server_port <= 0 || server_port > 65535)
            server_port = 1443;
    }

    // 创建ssl上下文
    ctx = createSSLCtx();
    if (ctx == NULL)
    {
        perror("creat ssl ctx fail");
        return 1;
    }
    /* 开启一个 socket 监听 */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        goto err;
    }
    else
    {
        printf("socket created\n");
    }

    // 设置socket地址
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = PF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1)
    {
        perror("bind");
        goto err;
    }
    else
    {
        printf("binded\n");
    }

    if (listen(sockfd, SOMAXCONN) == -1)
    {
        perror("listen");
        goto err;
    }
    else
    {
        printf("begin listen\n");
    }

    // 初始化创建tun虚拟网卡
    tun_fd = initTun();
    if (tun_fd <= 0)
    {
        perror("create tun fail");
        goto err;
    }

    // 创建server tun读取线程
    pthread_t serverTunThread;
    SERVER_TUN_THREAD_PARAM *param = malloc(sizeof(SERVER_TUN_THREAD_PARAM));
    if (param == NULL)
    {
        printf("malloc for SERVER_TUN_THREAD_PARAM fail");
        goto err;
    }
    memset(param, 0, sizeof(SERVER_TUN_THREAD_PARAM));
    param->tun_fd = tun_fd;
    ret = pthread_create(&serverTunThread, NULL, server_tun_thread, param);
    if (ret != 0)
    {
        perror("create server tun thread fail");
        goto err;
    }

    while (1)
    {
        len = sizeof(struct sockaddr);

        /* 等待客户端连上来 */
        if ((new_fd = accept(sockfd, (struct sockaddr *)&client_addr, &len)) == -1)
        {
            printf("wait for client coonect fail\n");
            goto err;
        }
        else
        {
            printf("server: got connection from %s, port %d, socket %d\n",
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), new_fd);
        }
        pthread_t clientSslThread;

        CLIENT_SSL_CACHE *clientSslCache = malloc(sizeof(CLIENT_SSL_CACHE));
        if (clientSslCache == NULL)
        {
            printf("malloc for CLIENT_SSL_CACHE fail");
            /* 关闭client socket */
            close(new_fd);
            continue;
        }
        memset(clientSslCache, 0, sizeof(CLIENT_SSL_CACHE));
        clientSslCache->tun_fd = tun_fd;
        clientSslCache->sockfd = new_fd;
        clientSslCache->ctx = ctx;
        ret = pthread_create(&clientSslThread, NULL, client_ssl_tun_thread, clientSslCache);
        if (ret != 0)
        {
            free(clientSslCache);
            continue;
        }
        // 加入到链表中  TODO 这一步实际需要等到ssl握手完成，并登录成功。在client_ssl_tun_thread线程中执行
        CLIENT_SESSION_T *clientSession = (CLIENT_SESSION_T *)malloc(sizeof(CLIENT_SESSION_T));
        if (clientSession == NULL)
        {
            // TODO 关闭ssl
            continue;
        }
        memset(clientSession, 0, sizeof(CLIENT_SESSION_T));
        clientSession->clientSslCache = clientSslCache;
        memcpy(clientSession->ipv4, "10.12.9.2", strlen("10.12.9.2"));
        ret = saveClientSession(clientSession);
        if (ret != 0)
        {
        }
    }
err:
    if (sockfd > 0)
    {
        /* 关闭server监听的 socket */
        close(sockfd);
    }
    /* 释放 CTX */
    SSL_CTX_free(ctx);
}

static SSL_CTX *createSSLCtx()
{
    // 变量定义
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    const char *sign_key_file = "cert/signkey.key";
    const char *sign_cert_file = "cert/signcert.crt";
    const char *enc_key_file = "cert/enckey.key";
    const char *enc_cert_file = "cert/enccert.crt";

    // 双证书相关server的各种定义
    meth = NTLS_server_method();
    // 生成上下文
    ctx = SSL_CTX_new(meth);
    // 允许使用国密双证书功能
    SSL_CTX_enable_ntls(ctx);

    // 加载签名证书，加密证书
    if (sign_key_file)
    {
        if (!SSL_CTX_use_sign_PrivateKey_file(ctx, sign_key_file, SSL_FILETYPE_PEM))
            goto err;
    }

    if (sign_cert_file)
    {
        if (!SSL_CTX_use_sign_certificate_file(ctx, sign_cert_file, SSL_FILETYPE_PEM))
            goto err;
    }

    if (enc_key_file)
    {
        if (!SSL_CTX_use_enc_PrivateKey_file(ctx, enc_key_file, SSL_FILETYPE_PEM))
            goto err;
    }

    if (enc_cert_file)
    {
        if (!SSL_CTX_use_enc_certificate_file(ctx, enc_cert_file, SSL_FILETYPE_PEM))
            goto err;
    }
    return ctx;
err:
    /* 释放 CTX */
    SSL_CTX_free(ctx);
    return NULL;
}

static void *client_ssl_tun_thread(void *arg)
{
    unsigned char buffer[MAX_BUF_LEN + HEADER_LEN];
    int len;
    unsigned char packet[MAX_BUF_LEN];
    unsigned int depack_len = 0;
    unsigned char *next = NULL;
    unsigned int next_len = 0;
    int ret = 0;

    CLIENT_SSL_CACHE *clientSslCache = (CLIENT_SSL_CACHE *)arg;
    int tun_fd = clientSslCache->tun_fd;
    /* 基于 ctx 产生一个新的 SSL */
    SSL *ssl = SSL_new(clientSslCache->ctx);
    /* 将连接用户的 socket 加入到 SSL */
    SSL_set_fd(ssl, clientSslCache->sockfd);

    /* 建立 SSL 连接 */
    if (SSL_accept(ssl) == -1)
    {
        printf("accept client ssl\n");
        goto finish;
    }
    clientSslCache->handshake = 1;
    clientSslCache->ssl = ssl;
    printf("ssl handshark success!\n");

    // 接收客户端的消息
    while (1)
    {
        if (next == NULL)
        {
            next = buffer;
            next_len = 0;
        }

        // 1、读取ssl数据
        len = SSL_read(ssl, next + next_len, sizeof(buffer) - next_len);
        if (len <= 0)
        {
            fprintf(stderr, "ssl read error(%d) errno(%d)\n", SSL_get_error(ssl, len), errno);
            break;
        }
        // printf("read client ssl data len: %d\n", len);

        // 2、解包处理
        depack_len = sizeof(packet);
        while ((ret = depack(next, len, packet, &depack_len, &next, &next_len)) > 0)
        {
            len = next_len;
            /* 3、写入到虚拟网卡 */
            // TODO 判定数据类型
            int datalen = depack_len - RECORD_HEADER_LEN;
            int wlen = write(tun_fd, packet + RECORD_HEADER_LEN, datalen);
            if (wlen < datalen)
            {
                printf("虚拟网卡写入数据长度小于预期长度, write len: %d, buffer len: %d\n", wlen, len);
            }
            depack_len = sizeof(packet);
        }
        if (ret < 0)
        {
            printf("非vpn协议数据\n");
        }
    }

finish:
    clientSslCache->dead = 1;
    /* 关闭 SSL 连接 */
    SSL_shutdown(ssl);
    /* 释放 SSL */
    SSL_free(ssl);
    /* 关闭 socket */
    close(clientSslCache->sockfd);
}

static int initTun()
{
    char dev[32] = {0};
    char *ipv4 = "10.12.9.1";
    char *ipv4_net = "10.12.9.0/24";

    memset(dev, 0, sizeof(dev));
    return tun_create(dev, ipv4, ipv4_net);
}

static void *server_tun_thread(void *arg)
{

    SERVER_TUN_THREAD_PARAM *param = (SERVER_TUN_THREAD_PARAM *)arg;
    int tun_fd = param->tun_fd;
    size_t ret_length = 0;
    unsigned char buf[MAX_BUF_LEN];
    unsigned char packet[MAX_BUF_LEN + HEADER_LEN];
    unsigned int enpack_len = 0;

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
        memcpy(dst_ip, &buf[16], 4);
        memcpy(src_ip, &buf[12], 4);
        // printf("read tun data: %d.%d.%d.%d -> %d.%d.%d.%d (%d)\n", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], src_ip[0], src_ip[1], src_ip[2], src_ip[3], ret_length);

        // 3、查询客户端
        char ip[MAX_IPV4_STR_LEN] = {0};
        bzero(ip, MAX_IPV4_STR_LEN);
        sprintf(ip, "%d.%d.%d.%d", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);
        CLIENT_SESSION_T *session = searchClientSession(ip);
        if (session == NULL)
        {
            printf("not found ssl session\n");
            continue;
        }
        if (!session->clientSslCache)
        {
            continue;
        }
        if (session->clientSslCache->handshake != 1)
        {
            continue;
        }
        // 4、对数据进行封包处理
        enpack_len = sizeof(packet);
        enpack(RECORD_TYPE_DATA, buf, ret_length, packet, &enpack_len);

        // 5、发消息给客户端
        // int len = SSL_write(session->clientSslCache->ssl, buf, ret_length);
        int len = SSL_write(session->clientSslCache->ssl, packet, enpack_len);
        if (len <= 0)
        {
            printf("消息'%s'发送失败! 错误代码是%d, 错误信息是'%s'\n", buf, errno, strerror(errno));
        }
        bzero(buf, MAX_BUF_LEN);
    }
}

static CLIENT_SESSION_T *searchClientSession(char *ipv4)
{
    // 非空判断
    if (ipv4 == NULL)
    {
        return NULL;
    }
    // printf("search client session for ipv4: %s\n", ipv4);

    CLIENT_SESSION_T *next = NULL;
    next = globalClientSession.next;
    while (next)
    {
        if ((strcmp(next->ipv4, ipv4) == 0))
        {
            // printf("search session success for: %s\n", ipv4);
            return next;
        }
        next = next->next;
    }
    return NULL;
}

static int saveClientSession(CLIENT_SESSION_T *clientSession)
{
    CLIENT_SESSION_T *session = clientSession;
    CLIENT_SESSION_T *next = NULL;

    if (clientSession == NULL)
    {
        return 1;
    }

    pthread_mutex_lock(&mtx);
    next = globalClientSession.next;
    session->next = next;
    globalClientSession.next = session;
    pthread_mutex_unlock(&mtx);

    return 0;
}