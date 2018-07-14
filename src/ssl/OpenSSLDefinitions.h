#pragma once

#if !defined(USE_BORINGSSL) && false
typedef struct bio_st {
	BIO_METHOD *method;
	/* bio, mode, argp, argi, argl, ret */
	long (*callback)(struct bio_st *,int,const char *,int, long,long);
	char *cb_arg; /* first argument for the callback */

	int init;
	int shutdown;
	int flags;  /* extra storage */
	int retry_reason;
	int num;
	void *ptr;
	struct bio_st *next_bio;    /* used by filter BIOs */
	struct bio_st *prev_bio;    /* used by filter BIOs */
	int references;
	unsigned long num_read;
	unsigned long num_write;

	CRYPTO_EX_DATA ex_data;
} BIO;

typedef struct bio_method_st
{
	int type;
	const char *name;
	int (*bwrite)(BIO *, const char *, int);
	int (*bread)(BIO *, char *, int);
	int (*bputs)(BIO *, const char *);
	int (*bgets)(BIO *, char *, int);
	long (*ctrl)(BIO *, int, long, void *);
	int (*create)(BIO *);
	int (*destroy)(BIO *);
	long (*callback_ctrl)(BIO *, int, bio_info_cb *);
} BIO_METHOD;
#endif