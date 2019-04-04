#include "common.h"

int compute_length(int type)
{
	switch(type) {
		case ZR_t: return BN_BYTES + 1; // null bytes included
		case G1_t: return G1_LEN; // (FP_BYTES * 2) + 2;
		case G2_t: return G2_LEN; // (FP_BYTES * 4) + 4;
		case GT_t: return GT_LEN; // (FP_BYTES * 12) + 12;
		default: break;
	}
	return 0;
}

void fp_write_bin(unsigned char *str, int len, fp_t a) {
        bn_t t;

        bn_null(t);

        TRY {
                bn_new(t);

                fp_prime_back(t, a);

                bn_write_bin(str, len, t);
        } CATCH_ANY {
                THROW(ERR_CAUGHT);
        }
        FINALLY {
                bn_free(t);
        }
}

void fp_read_bin(fp_t a, const unsigned char *str, int len) {
        bn_t t;

        bn_null(t);

        TRY {
                bn_new(t);
                bn_read_bin(t, (unsigned char *) str, len);
                if (bn_is_zero(t)) {
                        fp_zero(a);
                } else {
                        if (t->used == 1) {
                                fp_prime_conv_dig(a, t->dp[0]);
                        } else {
                                fp_prime_conv(a, t);
                        }
                }
        }
        CATCH_ANY {
                THROW(ERR_CAUGHT);
        }
        FINALLY {
                bn_free(t);
        }
}



status_t g1_read_bin(g1_t g, uint8_t *data, int data_len)
{
	if(g == NULL) return ELEMENT_UNINITIALIZED;
	fp_read_bin(g->x, data, FP_BYTES);
	fp_read_bin(g->y, &(data[FP_BYTES + 1]), FP_BYTES);
	fp_zero(g->z);
	fp_set_dig(g->z, 1);

	return ELEMENT_OK;
}

status_t g1_write_str(g1_t g, uint8_t *data, int data_len)
{
	if(g == NULL) return ELEMENT_UNINITIALIZED;
	if(data_len < G1_LEN*2) return ELEMENT_INVALID_ARG_LEN;
	char *d = (char *) data;

	int len = FP_BYTES*2+1;

	fp_write_str(d, len, g->x, BASE);
	fp_write_str(&(d[len]), len, g->y, BASE);

	return ELEMENT_OK;
}



status_t g2_write_str(g2_t g, uint8_t *data, int data_len)
{
#if defined(EP_KBLTZ) && FP_PRIME == 256
	if(g == NULL) return ELEMENT_UNINITIALIZED;
	int G2_STR = G2_LEN*4;
	if(data_len < G2_STR) return ELEMENT_INVALID_ARG_LEN;
	char *d = (char *) data;

	int len = FP_BYTES*2 + 1;
	fp_write_str(d, len, g->x[0], BASE);
	d += len;
	fp_write_str(d, len, g->x[1], BASE);
	d += len;
	fp_write_str(d, len, g->y[0], BASE);
	d += len;
	fp_write_str(d, len, g->y[1], BASE);
	return ELEMENT_OK;

#endif
}




status_t hash_buffer_to_bytes(uint8_t *input, int input_len, uint8_t *output, int output_len, uint8_t label)
{
	//LEAVE_IF(input == NULL || output == NULL, "uninitialized argument.");
	// adds an extra null byte by default - will use this last byte for the label
	int digest_len = SHA_LEN, i;

	if(digest_len <= output_len) {
		// hash buf using md_map_sh256 and store data_len bytes in data
		uint8_t digest[digest_len + 1];
		uint8_t input2[input_len + 2];
		memset(input2, 0, input_len + 1);
		// set prefix
		input2[0] = 0xFF & label;
		// copy remaining bytes
		for(i = 1; i <= input_len; i++)
			input2[i] = input[i-1];
#ifdef DEBUG
		printf("%s: original input: ", __FUNCTION__);
		print_as_hex(input, input_len);

		printf("%s: new input: ", __FUNCTION__);
		print_as_hex(input2, input_len + 1);
#endif
		memset(digest, 0, digest_len);
		SHA_FUNC(digest, input2, input_len+1);
		memcpy(output, digest, digest_len);

#ifdef DEBUG
		printf("%s: digest: ", __FUNCTION__);
		print_as_hex(output, digest_len);
#endif
		return ELEMENT_OK;
	}
	return ELEMENT_INVALID_ARG;
}