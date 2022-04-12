/**
 * (C) 2007-22 - ntop.org and contributors
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
#include <sm4.h>

// size of random value prepended to plaintext defaults to AES BLOCK_SIZE;
// gradually abandoning security, lower values could be chosen;
// however, minimum transmission size with cipher text stealing scheme is one
// block; as network packets should be longer anyway, only low level programmer
// might encounter an issue with lower values here

#define SM4_PREAMBLE_SIZE       (SM4_BLOCK_SIZE)


// cts/cbc mode is being used with random value prepended to plaintext
// instead of iv so, actual iv is sm4_null_iv
const uint8_t sm4_iv[SM4_IV_SIZE] ={ 0 };

typedef struct transop_sm4 {
    sm4_context_t       *ctx;
} transop_sm4_t;


static int transop_deinit_sm4 (n2n_trans_op_t *arg) {

    transop_sm4_t *priv = (transop_sm4_t *)arg->priv;

    if(priv->ctx)
        free(priv->ctx);

    if(priv)
        free(priv);

    return 0;
}


// the sm4 packet format consists of
//
//  - a random AES_PREAMBLE_SIZE-sized value prepended to plaintext
//    encrypted together with the...
//  - ... payload data
//
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
    uint8_t assembly[N2N_PKT_BUF_SIZE]={ 0 };
    size_t idx = 0;
    int padded_len;
    uint8_t padding;
    //uint8_t buf[SM4_IV_SIZE];
    int i;
    uint64_t iv_seed = 0;
    uint8_t iv[SM4_IV_SIZE]={ 0 };
    if(in_len <= N2N_PKT_BUF_SIZE) {
        if((in_len + SM4_PREAMBLE_SIZE + SM4_BLOCK_SIZE) <= out_len) {
            traceEvent(TRACE_DEBUG, "transop_encode_sm4 %lu bytes plaintext", in_len);
	        printf("sm4 enc start\n");
            // full block sized random value (128 bit)
            //iv_seed = ((((uint64_t)rand() & 0xFFFFFFFF)) << 32) | rand();
	        //encode_buf(outbuf, &idx, &iv_seed, SM4_IV_SIZE);
	        memset(outbuf,0,sizeof(outbuf));
            printf("outbuf before is ");
	        for(i=0;i<sizeof(outbuf);i++){
		        printf("0x%02x ",outbuf[i]);
	        }
	        printf("outbuf len is %d\n",sizeof(outbuf));
            printf("\n");
			printf("iv before is ");
	        for(i=0;i<SM4_IV_SIZE;i++){
		        printf("0x%02x ",iv[i]);
	        }
	        printf("iv len is %d\n",SM4_IV_SIZE);
            printf("\n");
            encode_uint64(outbuf, &idx, n2n_rand());
            encode_uint64(outbuf, &idx, n2n_rand());
	        memcpy(iv,outbuf,SM4_BLOCK_SIZE);
			printf("iv now is ");
			for(i=0;i<SM4_IV_SIZE;i++){
		        printf("0x%02x ",iv[i]);
	        }
	        printf("iv len is %d\n",SM4_IV_SIZE);
            printf("\n");
			printf("inbuf  is ");
			for(i=0;i<in_len;i++){
		        printf("0x%02x ",inbuf[i]);
	        }
	        printf("in len is %d\n",in_len);
            printf("\n");
	        idx=0;
            // the plaintext data
             printf("assemblyf is ");
            for(i=0;i<in_len;i++){
                printf("0x%02x ",assembly[i]);
            }
            printf("\n");
            encode_buf(assembly, &idx, inbuf, in_len);
            
            printf("assemblyf is ");
            for(i=0;i<in_len;i++){
                printf("0x%02x ",assembly[i]);
            }
            printf("\n");
            padded_len = (((idx - 1) / SM4_BLOCK_SIZE) + 1) * SM4_BLOCK_SIZE;
            //padding = (padded_len-idx);

            // pad the following bytes with zero, fixed length (AES_BLOCK_SIZE) seems to compile
            // to slightly faster code than run-time dependant 'padding'
            memset(assembly + idx, 0, SM4_BLOCK_SIZE);
            
	        sm4_crypt_cbc(priv->ctx,SM4_ENCRYPT,padded_len, iv,assembly,outbuf+SM4_IV_SIZE);
	        
            printf("outbuf now is ");
            for(i=0;i<padded_len+SM4_BLOCK_SIZE;i++){
                printf("0x%02x ",outbuf[i]);
            }
            printf("\n");
        } else
            traceEvent(TRACE_ERROR, "transop_encode_sm4 outbuf too small");
    } else
    traceEvent(TRACE_ERROR, "transop_encode_sm4 inbuf too big to encrypt");
    //idx=idx+SM4_IV_SIZE;

    return padded_len+SM4_BLOCK_SIZE;
}


// see transop_encode_sm4 for packet format
static int transop_decode_sm4 (n2n_trans_op_t *arg,
                               uint8_t *outbuf,
                               size_t out_len,
                               const uint8_t *inbuf,
                               size_t in_len,
                               const uint8_t *peer_mac) {

    transop_sm4_t *priv = (transop_sm4_t *)arg->priv;
    uint8_t assembly[N2N_PKT_BUF_SIZE]={ 0 };
    //size_t penultimate_block;
    int i;
    uint8_t ivde[SM4_IV_SIZE]={ 0 };
    int len = -1;

     if(((in_len - SM4_PREAMBLE_SIZE) <= N2N_PKT_BUF_SIZE) /* cipher text fits in assembly */
      && (in_len >= SM4_PREAMBLE_SIZE)                     /* has at least random number */
      && (in_len >= SM4_BLOCK_SIZE)) {                     /* minimum size requirement for cipher text stealing */
	    printf("sm4 dec start\n");
        traceEvent(TRACE_DEBUG, "transop_decode_sm4 %lu bytes ciphertext", in_len);
		printf("ivde before is ");
	        for( i=0;i<SM4_IV_SIZE;i++){
		        printf("0x%02x ",ivde[i]);
	        }
	    printf("inbuf len is %d\n",sizeof(ivde));
        printf("\n");
	    memcpy(ivde,inbuf,SM4_BLOCK_SIZE);
        printf("ivde now is ");
	        for( i=0;i<SM4_IV_SIZE;i++){
		        printf("0x%02x ",ivde[i]);
	        }
	    printf("ivde len is %d\n",sizeof(ivde));
        printf("\n");
        printf("inbuf is ");
	        for( i=0;i<in_len;i++){
		        printf("0x%02x ",inbuf[i]);
	        }
	    printf("inbuf len is %d\n",in_len);
        printf("\n");
       	printf("assembly before  is ");
        for(i=0;i<in_len-SM4_BLOCK_SIZE;i++){
            printf("0x%02x ",assembly[i]);
        }
        printf("\n");
        memcpy(assembly,inbuf+SM4_BLOCK_SIZE,in_len-SM4_BLOCK_SIZE);
        
        printf("assembly now is ");
        for(i=0;i<in_len-SM4_BLOCK_SIZE;i++){
            printf("0x%02x ",assembly[i]);
        }
        printf("\n");
        printf("in len is %d\n",in_len-SM4_BLOCK_SIZE);
        printf("\n");
        memset(outbuf,0,sizeof(outbuf));
		printf("outbuf before is ");
        for(i=0;i<in_len-SM4_BLOCK_SIZE;i++){
            printf("0x%02x ",outbuf[i]);
        }
        printf("\n");
	    sm4_crypt_cbc(priv->ctx,SM4_DECRYPT,in_len-SM4_BLOCK_SIZE,ivde,assembly,outbuf);
        
        printf("outbuf now is ");
        for(i=0;i<in_len-SM4_BLOCK_SIZE;i++){
            printf("0x%02x ",outbuf[i]);
        }
        printf("\n");
        //memcpy(outbuf,assembly,in_len-SM4_BLOCK_SIZE);
        len = in_len - SM4_PREAMBLE_SIZE;
    } else
        traceEvent(TRACE_ERROR, "transop_decode_sm4 inbuf wrong size (%ul) to decrypt", in_len);

    return len;
}


static int setup_sm4_key (transop_sm4_t *priv, const uint8_t *password, ssize_t password_len) {

    unsigned char   key_mat[32];     /* maximum sm4 key length, equals hash length */
    unsigned char   *key;
    size_t          key_size;

    // let the user choose the degree of encryption:
    // long input passwords will pick AES192 or AES256 with more robust but expensive encryption

    // the input password always gets hashed to make a more unpredictable use of the key space
    // just think of usually reset MSB of ASCII coded password bytes
    //sm3(password,password_len,key_mat);
    pearson_hash_256(key_mat, password, password_len);
    // the length-dependant scheme for key setup was discussed on github:
    // https://github.com/ntop/n2n/issues/101 -- as no iv encryption required
    //  anymore, the key-size trigger values were roughly halved
    key_size = SM4_BLOCK_SIZE;       /* 128 bit */
    // and use the last key-sized part of the hash as sm4 key
    key = key_mat + sizeof(key_mat) - key_size;

    // setup the key and have corresponding context created
    sm4_setkey_enc(priv->ctx,key);
    //sm4_setkey_dec(priv->ctx,key);
    traceEvent(TRACE_DEBUG, "setup_sm4_key %u-bit key setup completed", key_size * 8);
	printf("sm4 key init fin\n");
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
    if(!priv) {
        traceEvent(TRACE_ERROR, "n2n_transop_sm4_init cannot allocate transop_sm4_t memory");
        return -1;
    }
    ttt->priv = priv;
    priv->ctx=malloc(sizeof(sm4_context_t));
    printf("sm4 init start\n");

    // setup the cipher and key
    return setup_sm4_key(priv, encrypt_key, encrypt_key_len);
}
