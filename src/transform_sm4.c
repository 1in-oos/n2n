/**
 * (C) 2007-21 - ntop.org and contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 */


#include "n2n.h"
#include"sm4.h"

// size of random value prepended to plaintext defaults to SM4 BLOCK_SIZE;
// gradually abandoning security, lower values could be chosen;
// however, minimum transmission size with cipher text stealing scheme is one
// block; as network packets should be longer anyway, only low level programmer
// might encounter an issue with lower values here
#define SM4_PREAMBLE_SIZE       (SM4_BLOCK_SIZE)


// cts/cbc mode is being used with random value prepended to plaintext
// instead of iv so, actual iv is aes_null_iv
const uint8_t sm4_null_iv[SM4_IV_SIZE] = { 0 };

typedef struct transop_sm4 {
    sm4_context_t       *ctx;
} transop_sm4_t;


static int transop_deinit_sm4 (n2n_trans_op_t *arg) {

    transop_sm4_t *priv = (transop_sm4_t *)arg->priv;

    if(priv->ctx)
        sm4_deinit(priv->ctx);

    if(priv)
        free(priv);

    return 0;
}


// the aes packet format consists of
//  - a random AES_PREAMBLE_SIZE-sized value prepended to plaintext
//    encrypted together with the...
//  - ... payload data
//  [VV|DDDDDDDDDDDDDDDDDDDDD]
//  | <---- encrypted ---->  |
//


static int transop_encode_sm4 (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {

    transop_sm4_t *priv = (transop_sm4_t *)arg->priv;

    // the assembly buffer is a source for encrypting data
    // the whole contents of assembly are encrypted
    //程序集缓冲区是加密数据的源
    //汇编的全部内容都是加密的
    
    uint8_t assembly[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    int padded_len;
    uint8_t padding;
    uint8_t buf[SM4_BLOCK_SIZE];

    if(in_len <= N2N_PKT_BUF_SIZE) {
        if((in_len + SM4_PREAMBLE_SIZE + SM4_BLOCK_SIZE) <= out_len) {
            traceEvent(TRACE_DEBUG, "transop_encode_sm4 %lu bytes plaintext", in_len);

            // full block sized random value (128 bit)
            //全块大小的随机值（128位）
            encode_uint64(assembly, &idx, n2n_rand());
            encode_uint64(assembly, &idx, n2n_rand());

            // adjust for maybe differently chosen SM4_PREAMBLE_SIZE前置区
            //根据可能不同的SM4_大小进行调整
            idx = SM4_PREAMBLE_SIZE;//16

            // the plaintext data明文
            encode_buf(assembly, &idx, inbuf, in_len);

            // round up to next whole AES block size取整到下一个完整的AES块大小
            padded_len = (((idx - 1) / SM4_BLOCK_SIZE) + 1) * SM4_BLOCK_SIZE;
            padding = (padded_len-idx);

            // pad the following bytes with zero, fixed length (AES_BLOCK_SIZE) seems to compile
            // to slightly faster code than run-time dependant 'padding'
            //使用零固定长度（AES_BLOCK_SIZE）填充以下字节似乎比依赖于运行时的“填充”编译为稍快的代码
            memset(assembly + idx, 0, SM4_BLOCK_SIZE);
            //int aes_cbc_encrypt (unsigned char *out, const unsigned char *in, size_t in_len,const unsigned char *iv, aes_context_t *ctx) 
 	        //aes_cbc_encrypt(outbuf, assembly, padded_len, aes_null_iv, priv->ctx);
	        //void sm4_crypt_cbc( sm4_context *ctx, int mode,int length,unsigned char iv[16],unsigned char *input, unsigned char *output );
	        sm4_crypt_cbc( priv->ctx,1,padded_len,sm4_null_iv,assembly, outbuf);	

				
            if(padding) {
                // exchange last two cipher blocks交换最后两个密码块
                memcpy(buf, outbuf+padded_len - SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
                memcpy(outbuf + padded_len - SM4_BLOCK_SIZE, outbuf + padded_len - 2 * SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
                memcpy(outbuf + padded_len - 2 * SM4_BLOCK_SIZE, buf, SM4_BLOCK_SIZE);
            }
        } else
            traceEvent(TRACE_ERROR, "transop_encode_sm4 outbuf too small");
    } else
    traceEvent(TRACE_ERROR, "transop_encode_sm4 inbuf too big to encrypt");

    return idx;
}


// see transop_encode_sm4 for packet format 数据包格式
static int transop_decode_sm4 (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {

    transop_sm4_t *priv = (transop_sm4_t *)arg->priv;
    uint8_t assembly[N2N_PKT_BUF_SIZE];

    uint8_t rest;
    size_t penultimate_block;//倒数第二个
    uint8_t buf[SM4_BLOCK_SIZE];
    int len = -1;

     if(((in_len - SM4_PREAMBLE_SIZE) <= N2N_PKT_BUF_SIZE) /* cipher text fits in assembly 密文适合汇编*/
      && (in_len >= SM4_PREAMBLE_SIZE)                     /* has at least random number至少有一个随机数*/
      && (in_len >= SM4_BLOCK_SIZE)) {                     /* minimum size requirement for cipher text stealing 密文获取的最小尺寸要求*/
        traceEvent(TRACE_DEBUG, "transop_decode_sm4 %lu bytes ciphertext", in_len);

        rest = in_len % SM4_BLOCK_SIZE;
        if(rest) { /* cipher text stealing 密文窃取*/
            traceEvent(TRACE_DEBUG, "transop_decode_sm4 %lu bytes ciphertext", in_len);
            return -1;
        } else {
            // regular cbc decryption on multiple block-sized payload多块大小有效负载上的常规cbc解密
            // ossl_sm4_decrypt(assembly, inbuf, in_len, sm4_null_iv, priv->ctx);   
            traceEvent(TRACE_DEBUG, "transop_decode_sm4 %lu bytes ciphertext", in_len);      
	        sm4_crypt_cbc( priv->ctx,0,in_len ,sm4_null_iv,inbuf, assembly);  
        }
        len = in_len - SM4_PREAMBLE_SIZE;
        memcpy(outbuf, assembly + SM4_PREAMBLE_SIZE, len);
    } else
        traceEvent(TRACE_ERROR, "transop_decode_sm4 inbuf wrong size (%ul) to decrypt", in_len);

    return len;
}


static int  setup_sm4_key (transop_sm4_t *priv, const uint8_t *password, ssize_t password_len) {

    unsigned char   key_mat[32];     /* maximum aes key length, equals hash length */
    unsigned char	*key;
    size_t          key_size;
    
    pearson_hash_256(key_mat, password, password_len);

	key_size=SM4_BLOCK_SIZE;

    // and use the last key-sized part of the hash as aes key
    key = key_mat + sizeof(key_mat) - key_size;
    // memcpy(key,key_mat,16);
   
    // setup the key and have corresponding context created
    //sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] );
    	
	sm4_setkey_enc( (priv->ctx), key);

    return 0;
}


static void transop_tick_sm4 (n2n_trans_op_t *arg, time_t now) {

    // no tick action
}


// AES initialization function
int n2n_transop_sm4_init (const n2n_edge_conf_t *conf, n2n_trans_op_t *ttt) {

    transop_sm4_t *priv;
    const u_char *encrypt_key = (const u_char *)conf->encrypt_key;
    size_t encrypt_key_len = strlen(conf->encrypt_key);

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_TRANSFORM_ID_SM4;

    ttt->tick         = transop_tick_sm4;
    ttt->deinit       = transop_deinit_sm4;
    ttt->fwd          = transop_encode_sm4;
    ttt->rev          = transop_decode_sm4;

    priv = (transop_sm4_t*)calloc(1, sizeof(transop_sm4_t));
    priv->ctx = calloc(1, sizeof(sm4_context_t));

    if(!priv) {
        traceEvent(TRACE_ERROR, "n2n_transop_sm4_init cannot allocate transop_sm4_t memory");
        return -1;
    }


    if(!priv->ctx) {
        traceEvent(TRACE_ERROR, "n2n_transop_sm4_init cannot allocate sm4_context_t memory");
        return -1;
    }

    ttt->priv = priv;

    // setup the cipher and key
    return setup_sm4_key(priv, encrypt_key, encrypt_key_len);
}
