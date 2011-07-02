/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef USERMGMT_H
#define USERMGMT_H

#include <stdint.h>

#include "curve.h"
#include "crypto_hash_sha512.h"

enum is_user_enum {
	USERNAMES_OK = 0,	/* Usernames match, valid 'token' */
	USERNAMES_NE,		/* Usernames do not match */
	USERNAMES_TS,		/* Usernames match, but 'token' invalid,
				   Drop connection here */
	USERNAMES_ERR,
};

struct username_struct {
	uint32_t salt;
	uint8_t hash[crypto_hash_sha512_BYTES];
	uint8_t taia[16];
};

extern int username_msg(char *username, size_t len, char *dst, size_t dlen);
extern enum is_user_enum username_msg_is_user(char *src, size_t slen,
					      char *username, size_t len,
					      struct taia *arrival_taia);
extern void parse_userfile_and_generate_user_store_or_die(char *homedir);
extern void dump_user_store(void);
extern void destroy_user_store(void);

extern int get_user_by_socket(int sock, struct curve25519_proto **proto);
extern int get_user_by_sockaddr(struct sockaddr_storage *sa, size_t sa_len,
				struct curve25519_proto **proto);
extern int try_register_user_by_socket(char *src, size_t slen, int sock);
extern int try_register_user_by_sockaddr(char *src, size_t slen,
					 struct sockaddr_storage *sa,
					 size_t sa_len);
extern void remove_user_by_socket(int sock);
extern void remove_user_by_sockaddr(struct sockaddr_storage *sa,
				    size_t sa_len);

#endif /* USERMGMT_H */
