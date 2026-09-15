#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "auks/auks_cred.h"
#include "auks/auks_error.h"
#include "auks/auks_message.h"

static int
write_message(const char *dir, const char *name, auks_message_t *message)
{
	char path[4096];
	FILE *file;
	char *data = NULL;
	size_t length = 0;

	if (snprintf(path, sizeof(path), "%s/%s.bin", dir, name)
	    >= (int)sizeof(path))
		return 1;
	if (auks_message_marshall(message, &data, &length) != AUKS_SUCCESS)
		return 1;
	file = fopen(path, "wb");
	if (file == NULL) {
		free(data);
		return 1;
	}
	if (fwrite(data, 1, length, file) != length) {
		fclose(file);
		free(data);
		return 1;
	}
	fclose(file);
	free(data);
	return 0;
}

static int
empty_message(const char *dir, const char *name, int type)
{
	auks_message_t message;
	int status = auks_message_init(&message, type, NULL, 0);

	if (status == AUKS_SUCCESS) {
		status = write_message(dir, name, &message);
		auks_message_free_contents(&message);
	}
	return status;
}

static void
make_blob(unsigned char *blob, size_t length)
{
	for (size_t i = 0; i < length; ++i)
		blob[i] = (unsigned char)(i & 0xff);
}

static void
fill_cred(auks_cred_t *credential, const char *principal, unsigned int uid,
	  int addressless, int crossrealm, const unsigned char *data,
	  size_t length)
{
	memset(credential, 0, sizeof(*credential));
	strncpy(credential->info.principal, principal,
		AUKS_PRINCIPAL_MAX_LENGTH);
	credential->info.uid = uid;
	credential->info.starttime = 1700000000;
	credential->info.endtime = 1700036000;
	credential->info.renew_till = 1700604800;
	credential->info.addressless = addressless;
	credential->info.crossrealm = crossrealm;
	credential->max_length = AUKS_CRED_DATA_MAX_LENGTH;
	credential->length = length;
	credential->status = 0;
	memcpy(credential->data, data, length);
}

static int
write_cred_reply(const char *dir, const char *name, int type,
		 const auks_cred_t *credentials, size_t count)
{
	auks_message_t message;
	int status = auks_message_init(&message, type, NULL, 0);

	if (status != AUKS_SUCCESS)
		return status;
	if (type == AUKS_DUMP_REPLY) {
		status = auks_message_pack_int(&message, (int)count);
		if (status != AUKS_SUCCESS)
			goto out;
	}
	for (size_t i = 0; i < count; ++i) {
		status = auks_cred_pack((auks_cred_t *)&credentials[i], &message);
		if (status != AUKS_SUCCESS)
			goto out;
	}
	status = write_message(dir, name, &message);
out:
	auks_message_free_contents(&message);
	return status;
}

int
main(int argc, char **argv)
{
	const char *dir;
	unsigned char blob[1000];
	unsigned char admin_blob[17];
	auks_cred_t credentials[2];
	auks_message_t message;
	int status;

	if (argc != 2) {
		fprintf(stderr, "usage: %s OUTPUT_DIR\n", argv[0]);
		return 2;
	}
	dir = argv[1];
	make_blob(blob, sizeof(blob));
	memset(admin_blob, 0xaa, sizeof(admin_blob));
	fill_cred(&credentials[0], "user@EXAMPLE.COM", 1234, 1, 0, blob,
		  sizeof(blob));
	fill_cred(&credentials[1], "admin@EXAMPLE.COM", 4321, 0, 1, admin_blob,
		  sizeof(admin_blob));

	status = empty_message(dir, "ping_request", AUKS_PING_REQUEST);
	if (status != 0)
		return status;
	status = empty_message(dir, "close_request", AUKS_CLOSE_REQUEST);
	if (status != 0)
		return status;
	status = empty_message(dir, "dump_request", AUKS_DUMP_REQUEST);
	if (status != 0)
		return status;

	status = auks_message_init(&message, AUKS_GET_REQUEST, NULL, 0);
	if (status != AUKS_SUCCESS)
		return status;
	auks_message_pack_uid(&message, 1234);
	status = write_message(dir, "get_request_1234", &message);
	auks_message_free_contents(&message);
	if (status != 0)
		return status;

	status = auks_message_init(&message, AUKS_REMOVE_REQUEST, NULL, 0);
	if (status != AUKS_SUCCESS)
		return status;
	auks_message_pack_uid(&message, 4321);
	status = write_message(dir, "remove_request_4321", &message);
	auks_message_free_contents(&message);
	if (status != 0)
		return status;

	status = auks_message_init(&message, AUKS_ADD_REQUEST,
				   (char *)blob, sizeof(blob));
	if (status != AUKS_SUCCESS)
		return status;
	status = write_message(dir, "add_request", &message);
	auks_message_free_contents(&message);
	if (status != 0)
		return status;

	status = write_cred_reply(dir, "get_reply", AUKS_GET_REPLY,
				  credentials, 1);
	if (status != 0)
		return status;
	status = write_cred_reply(dir, "dump_reply", AUKS_DUMP_REPLY,
				  credentials, 2);
	if (status != 0)
		return status;
	return empty_message(dir, "error_reply", AUKS_ERROR_REPLY);
}
