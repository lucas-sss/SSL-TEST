/*
 * @Author: lw liuwei@flksec.com
 * @Date: 2023-09-06 10:02:22
 * @LastEditors: lw liuwei@flksec.com
 * @LastEditTime: 2023-11-06 10:29:46
 * @FilePath: \stream-echo-nginx-module-master\src\protocol.h
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
#ifndef PROTOCOL_H
#define PROTOCOL_H

#define VPN_LABEL_LEN 2
#define RECORD_TYPE_LABEL_LEN 2
#define RECORD_LENGTH_LABEL_LEN 4

extern const unsigned int HEADER_LEN;
extern const unsigned int RECORD_HEADER_LEN;

extern const unsigned char VPN_LABEL[VPN_LABEL_LEN]; // vpn数据标记
extern const unsigned char RECORD_TYPE_DATA[RECORD_TYPE_LABEL_LEN];
extern const unsigned char RECORD_TYPE_CONTROL[RECORD_TYPE_LABEL_LEN];
extern const unsigned char RECORD_TYPE_AUTH[RECORD_TYPE_LABEL_LEN];
extern const unsigned char RECORD_TYPE_ALARM[RECORD_TYPE_LABEL_LEN];

/**
 * @brief 对数据进行封包处理（类似tlv格式），VPN_LABEL + RECORD_TYPE + RECORD_LENGTH + 数据
 *
 * @param type      数据类型
 * @param in        原始数据
 * @param in_len    原始数据长度
 * @param out       封包处理后数据存储地址
 * @param out_len   输入时为封包数据存储地址可用长度，输出时为封包后数据长度
 * @return int      0成功，小于0失败
 */
int enpack(const unsigned char type[RECORD_TYPE_LABEL_LEN], unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int *out_len);

/**
 * @brief 对数据进行解包处理
 *
 * @param in        待解包数据
 * @param in_len    待解包数据长度
 * @param out       解包出的数据
 * @param out_len   解包出的数据包长度
 * @param next      不为NULL表示还有剩余数据，指向下一个数据包开始位置，为NULL表示没有剩余数据，全部解析完成（当返回值>=0）
 * @param next_len  剩余数据长度
 * @return int      0未解析到完整数据包，继续解析；1解析到完整数据包；-1数据格式错误
 */
int depack(unsigned char *in, unsigned int in_len, unsigned char *out, unsigned int *out_len, unsigned char **next, unsigned int *next_len);

#endif // PROTOCOL_H