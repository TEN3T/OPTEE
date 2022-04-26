#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	int len = 1024;
	char plaintext[1024] = {0, };
	char ciphertext[1024] = {0, };

	res = TEEC_InitializeContext(NULL, &ctx);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;

	FILE* file = fopen(argv[2], "r");
	if(file == NULL){
		printf("Not Exist File\n");
		return -1;
	}

	while(fgets(plaintext, sizeof(plaintext), file) != NULL);
	fclose(file);
	memcpy(op.params[0].tmpref.buffer, plaintext, len);

	if(strcmp(argv[1], "-e") == 0){
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
		/*if(res != TEEC_SUCCESS){
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		}*/
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Ciphertext: %s\n", ciphertext);

		FILE* eFile = fopen("ciphertext.txt", "w");
		fprintf(eFile, ciphertext);
		fclose(eFile);

		FILE* kFile = fopen("eKey.txt", "w");
		fprintf(kFile, "%d", op.params[1].value.a);
		fclose(kFile);
	}else if(!strcmp(argv[1], "-d")){
		FILE* kFile = fopen(argv[3], "r");

		if(kFile == NULL){
			printf("Not Exist File\n");
			return -1;
		}

		int key;
		fscanf(kFile, "%d", &key);
		fclose(kFile);

		op.params[1].value.a = key;
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext: %s\n", plaintext);

		FILE* dFile = fopen("plaintext.txt", "w");
		fprintf(dFile, plaintext);
		fclose(dFile);
	}else {
		printf("Not exist Option\n");
	}

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
