#include "tls.h"

extern SCONFIG* global_config;

int ssc_init_openssl()
{
	SSL_load_error_strings();
	return !(OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL)); /* reverse 1&0 (openssl bs) */
}

void ssc_cleanup_openssl()
{
	/* cleanup openssl */
//	ENGINE_cleanup();
	EVP_cleanup();	
	FIPS_mode_set(0);
//	CONF_modules_unload(1);
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	return;
}

SSL_CTX* ssl_create_context()
{
	/* init variables */
	const SSL_METHOD* meth;
	SSL_CTX* ctx;	
	
	/* create new SSL CTX */
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

	if(ctx == NULL)
	{
		logerr("failed to generate ssl ctx");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}	
	return ctx;
}

int ssl_configure_context(SSL_CTX* ctx)
{
	/* get important variables from the configfile */
	byte* ssl_certfile_path = sconfig_get_str(global_config,"SSCS_CERTFILE"); /* public key */

	if(!ssl_certfile_path)
	{
		logerr("failed to retrieve the ssl_certfile_path from the configuration");
		return 1;
	}

	byte* ssl_keyfile_path = sconfig_get_str(global_config,"SSCS_KEYFILE");	 /* private key */
	if(!ssl_keyfile_path)
	{
		logerr("failed to retrieve the ssl_keyfile_path from the configuration"); 
		custom_free(ssl_certfile_path);
		return 2;
	}

	byte* ssl_keyfile_password = sconfig_get_str(global_config,"SSCS_KEYFILE_PW"); /* private key encryption key */
	if(!ssl_keyfile_password)
	{
		logerr("failed to retrieve the ssl_keyfile_password from the configuration");
		custom_free(ssl_keyfile_path);
		custom_free(ssl_certfile_path);
		return 3;
	}

	SSL_CTX_set_default_passwd_cb_userdata(ctx, ssl_keyfile_password); /* give openssl or keyfile encryption key */

	/* configure the ssl context ctx with our public and private key */	
	if( SSL_CTX_use_certificate_file(ctx, ssl_certfile_path, SSL_FILETYPE_PEM) <= 0 ) /* set public key */
	{
		ERR_print_errors_fp(stderr);	
		logerr("failed to configure ssl ctx(pubkey)");
		custom_free(ssl_keyfile_path);	
		custom_free(ssl_certfile_path);
		custom_free(ssl_keyfile_password);
		
		return 4;	
	}

	/* set the ctx to private key located at ssl_keyfile_path */
	if( SSL_CTX_use_PrivateKey_file(ctx, ssl_keyfile_path, SSL_FILETYPE_PEM) <= 0 ) /* set private key */
	{
		ERR_print_errors_fp(stderr);	
		logerr("failed to configure ssl ctx(privkey)");
		custom_free(ssl_keyfile_path);	
		custom_free(ssl_certfile_path);
		custom_free(ssl_keyfile_password);
		
		return 5;	
	}

	/* cleanup */
	custom_free(ssl_keyfile_path);	
	custom_free(ssl_certfile_path);
	custom_free(ssl_keyfile_password);
	
	return 0;	
}


