//
// Created by 刘伟 on 2023/6/28.
//

#ifndef SSL_TEST_TUN_H
#define SSL_TEST_TUN_H


#define MAX_TUN_DEV_NAME_LEN 16
#define MAX_IPV4_STR_LEN 15
#define MAX_IPV4_NET_STR_LEN 31
#define MAX_IPV6_STR_LEN 45

typedef struct tunconfig_t {
    char dev[MAX_TUN_DEV_NAME_LEN];          // 虚拟设备名称
    char ipv4[MAX_IPV4_STR_LEN + 1];         // ipv4地址    10.9.0.1
    char ipv4_net[MAX_IPV4_NET_STR_LEN + 1]; // ipv4网络地址 10.9.0.0/24
    char ipv6[MAX_IPV6_STR_LEN + 1];         // ipv6地址
    int mtu;                                 // 虚拟设备mtu值
} TUNCONFIG_T;

/**
 *
 * @param dev
 * @param ipv4
 * @param ipv4_net
 * @return
 */
int tun_create(char *dev, char *ipv4, char *ipv4_net);

#endif //SSL_TEST_TUN_H
