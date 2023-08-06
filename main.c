#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


#define lisnum 5

int main() {

    int ret = 0;
    SSL_CTX *ctx = NULL;

    socklen_t len;
    int sockfd, new_fd;
    struct sockaddr_in server_addr, client_addr;

    //1 ssl初始化
    /* SSL 库初始化*/
    SSL_library_init();
    /* 载入所有SSL 算法*/
    OpenSSL_add_all_algorithms();
    /* 载入所有SSL 错误消息*/
    SSL_load_error_strings();
    /* 以SSL V2 和V3 标准兼容方式产生一个SSL_CTX ，即SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());

    //2 配置验证对方证书，并加载ca证书
    //验证对方
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    //若验证,则放置CA证书
    ret = SSL_CTX_load_verify_locations(ctx, "cert/ca.crt", NULL);
    printf("ssl load ca ret=%d\n", ret);

    //3 配置本端双证书和私钥
    /* 载入用户的数字证书， 此证书用来发送给客户端。证书里包含有公钥*/
    if (SSL_CTX_use_certificate_file(ctx, "cert/signcert.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥*/
    if (SSL_CTX_use_PrivateKey_file(ctx, "cert/signkey.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户的数字证书， 此证书用来发送给客户端。证书里包含有公钥*/
    if (SSL_CTX_use_certificate_file(ctx, "cert/enccert.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥*/
    if (SSL_CTX_use_PrivateKey_file(ctx, "cert/enckey.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 检查用户私钥是否正确*/
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    //4 开启一个socket
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else {
        printf("socket created\n");
    }
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = PF_INET;
    server_addr.sin_port = htons(8090);
    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) == -1) {
        perror("bind fail");
        exit(1);
    } else {
        printf("binded\n");
    }
    if (listen(sockfd, lisnum) == -1) {
        perror("listen");
        exit(1);
    } else {
        printf("begin listen\n");
    }

    //5 建立ssl连接
    while (1) {
        SSL *ssl;
        len = sizeof(struct sockaddr);

        /* 等待客户端连上来 */
        if ((new_fd = accept(sockfd, (struct sockaddr *) &client_addr, &len)) == -1) {
            perror("accept");
            exit(errno);
        } else {
            printf("server: got connection from %s, port %d, socket %d\n", inet_ntoa(client_addr.sin_addr),
                   ntohs(client_addr.sin_port), new_fd);
        }

        /* 基于 ctx 产生一个新的 SSL */
        ssl = SSL_new(ctx);
        /* 将连接用户的 socket 加入到 SSL */
        SSL_set_fd(ssl, new_fd);
        /* 建立 SSL 连接 */
        if (SSL_accept(ssl) == -1) {
            perror("accept");
            close(new_fd);
            break;
        }

        /* TODO 开始处理每个新连接上的数据收发 */

        // 发消息给客户端 SSL_write(ssl, buf, strlen(buf));

        // 接收客户端的消息 SSL_read(ssl, buf, MAXBUF);

        /* 处理每个新连接上的数据收发结束 */
        finish:
        /* 关闭 SSL 连接 */
        SSL_shutdown(ssl);
        /* 释放 SSL */
        SSL_free(ssl);
        /* 关闭 socket */
        close(new_fd);
    }
    /* 关闭监听的 socket */
    close(sockfd);
    /* 释放 CTX */
    SSL_CTX_free(ctx);

    printf("ssl server shutdown.\n");
    return 0;
}
