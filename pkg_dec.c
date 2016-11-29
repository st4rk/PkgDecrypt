/**
 * PS Vita PKG Decrypt
 * Decrypts PS Vita PKG files
 * The code is a total mess, use at your own risk.
 * Written by St4rk
 * Special thanks to Proxima <3
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>

unsigned char pkg_key_psp[] = {
	0x07, 0xF2, 0xC6, 0x82, 0x90, 0xB5, 0x0D, 0x2C, 0x33, 0x81, 0x8D, 0x70, 0x9B, 0x60, 0xE6, 0x2B
};

unsigned char pkg_vita_2[] = {
	0xE3, 0x1A, 0x70, 0xC9, 0xCE, 0x1D, 0xD7, 0x2B, 0xF3, 0xC0, 0x62, 0x29, 0x63, 0xF2, 0xEC, 0xCB
};

unsigned char pkg_vita_3[] = {
	0x42, 0x3A, 0xCA, 0x3A, 0x2B, 0xD5, 0x64, 0x9F, 0x96, 0x86, 0xAB, 0xAD, 0x6F, 0xD8, 0x80, 0x1F
};

unsigned char pkg_vita_4[] = {
	0xAF, 0x07, 0xFD, 0x59, 0x65, 0x25, 0x27, 0xBA, 0xF1, 0x33, 0x89, 0x66, 0x8B, 0x17, 0xD9, 0xEA
};

typedef struct ctr {
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char counter[AES_BLOCK_SIZE];
	unsigned int num;
} ctr;


int main(int argc, char **argv) {
	FILE *pkg = NULL;
	char pkgName[0xFF];

	memset(pkgName, 0x0, 0xFF);
	printf("Pkg name:\n");
	scanf("%s", pkgName);

	pkg = fopen(pkgName, "rb");

	if (pkg == NULL) {
		printf("PKG %s not found !\n", pkgName);
		return 0;
	}

	/** get pkg key type */
	unsigned int keyType = 0;
	fseek(pkg, 0xE4, SEEK_SET);
	fread(&keyType, sizeof(unsigned int), 1, pkg);

	keyType = (keyType >> 24) & 7;

	/** pkg key */
	unsigned char pkg_key[0x10] = {0};

	fseek(pkg, 0x70, SEEK_SET);
	fread(pkg_key, 1, 0x10, pkg);

	/** encrypted data information */
	uint64_t dataOffset = 0;
	uint64_t dataSize = 0;
	fseek(pkg, 0x20, SEEK_SET);
	fread(&dataOffset, sizeof(uint64_t), 1, pkg);
	fseek(pkg, 0x28, SEEK_SET);
	fread(&dataSize, sizeof(uint64_t), 1, pkg);
	dataSize =  __builtin_bswap64(dataSize);
	dataOffset = __builtin_bswap64(dataOffset);

	printf("Offset: 0x%lX\n", dataOffset);
	printf("Size: 0x%lX\n", dataSize);

	AES_KEY key;

	FILE *content = fopen("out.bin", "wb");

	/**
	 * encrypt PKG Key with AES_Key to generate the CTR Key
	 * only with PKG Type 2, 3 and 4
	 */
	unsigned char ctr_key[0x10];

	switch (keyType) {
		case 2:
			AES_set_encrypt_key(pkg_vita_2, 128, &key);
			AES_ecb_encrypt(pkg_key, ctr_key, &key, AES_ENCRYPT);
		break;

		case 3:
			AES_set_encrypt_key(pkg_vita_3, 128, &key);
			AES_ecb_encrypt(pkg_key, ctr_key, &key, AES_ENCRYPT);
		break;

		case 4:
			AES_set_encrypt_key(pkg_vita_4, 128, &key);
			AES_ecb_encrypt(pkg_key, ctr_key, &key, AES_ENCRYPT);
		break;
	}

	/**
	 * Set AES CTR key and use PKG key as IV
	 */

	/* decrypt chunks */
	unsigned char buffer[AES_BLOCK_SIZE];
	unsigned char out[AES_BLOCK_SIZE];
	int bytesOut = 0;
	ctr d_ctr;	

	memcpy(d_ctr.iv, pkg_key, AES_BLOCK_SIZE);
	memset(d_ctr.counter, 0, AES_BLOCK_SIZE);

	d_ctr.num = 0;

	/**
	 * AES CTR Decrypt, using the old key as IV
	 */
	AES_set_encrypt_key(keyType != 1 ? ctr_key : pkg_key_psp, 128, &key);

	printf("Decrypting...");
	fseek(pkg, dataOffset, SEEK_SET);

	while (fread(buffer, 1, AES_BLOCK_SIZE, pkg) == AES_BLOCK_SIZE) {
		AES_ctr128_encrypt(buffer, out, AES_BLOCK_SIZE, &key, d_ctr.iv, d_ctr.counter, &d_ctr.num);
		fwrite(out, 1, AES_BLOCK_SIZE, content);
	}

	printf("Done !\n");
	fclose(content);
	fclose(pkg);


	return 0;
}