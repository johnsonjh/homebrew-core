class CKermit < Formula
  desc "Scriptable network and serial communication for UNIX and VMS"
  homepage "https://www.kermitproject.org/"
  url "https://www.kermitproject.org/ftp/kermit/archives/cku302.tar.gz"
  version "9.0.302"
  sha256 "0d5f2cd12bdab9401b4c836854ebbf241675051875557783c332a6a40dac0711"
  license "BSD-3-Clause"
  revision 1

  # C-Kermit archive file names only contain the patch version and the full
  # version has to be obtained from text on the project page.
  livecheck do
    url "https://www.kermitproject.org/ckermit.html"
    regex(/The current C-Kermit release is v?(\d+(?:\.\d+)+) /i)
  end

  bottle do
    rebuild 2
    sha256 cellar: :any_skip_relocation, arm64_ventura:  "6ee8af35826f4b5be62d1c4b4e8b38eb39915da0b28d6b8f53ff9dfbb99f6698"
    sha256 cellar: :any_skip_relocation, arm64_monterey: "8315af8bc632253d0b2fdfde4b9da0fef5ad11af891b4e4eb8b51a35902f1e33"
    sha256 cellar: :any_skip_relocation, arm64_big_sur:  "259f1f0d2e2a1af6545bec724db3e1f154169dbd33e2b8ef43364381b3664cfe"
    sha256 cellar: :any_skip_relocation, ventura:        "0772fae0e560c8e726c611bd1e5b55d03e77f6f42feb3f763cb12f15a0151dc9"
    sha256 cellar: :any_skip_relocation, monterey:       "e379dd0cdd6eb9eec792cdd48ca7c5b7cd9281288840b15ce1d860fbb78982b2"
    sha256 cellar: :any_skip_relocation, big_sur:        "c2867c176bc81a35f56d5fe29847500b7c5f8c3e05ac10b5986073502a888a0f"
    sha256 cellar: :any_skip_relocation, x86_64_linux:   "0d5959e91d9fce4bee2b835433a8d2cc589f8f9f37e02c0f1078dbe645e6351a"
  end

  depends_on "openssl@1.1"

  uses_from_macos "libxcrypt"
  uses_from_macos "ncurses"

  on_linux do
    depends_on "linux-pam"
  end

  # Apply patch to fix build failure with glibc 2.28+
  # Will be fixed in next release: https://www.kermitproject.org/ckupdates.html
  patch :DATA

  def install
    os = OS.mac? ? "macosx+krb5+ssl" : "linux+krb5+ssl"
    system "make", os
    man1.mkpath

    # The makefile adds /man to the end of manroot when running install
    # hence we pass share here, not man.  If we don't pass anything it
    # uses {prefix}/man
    system "make", "prefix=#{prefix}", "manroot=#{share}", "install"
  end

  test do
    assert_match "C-Kermit #{version}",
                 shell_output("#{bin}/kermit -C VERSION,exit")
  end
end

__END__
diff -ru z/ckucmd.c k/ckucmd.c
--- z/ckucmd.c	2004-01-07 10:04:04.000000000 -0800
+++ k/ckucmd.c	2019-01-01 15:52:44.798864262 -0800
@@ -7103,7 +7103,7 @@
 
 /* Here we must look inside the stdin buffer - highly platform dependent */
 
-#ifdef _IO_file_flags			/* Linux */
+#ifdef _IO_EOF_SEEN			/* Linux */
     x = (int) ((stdin->_IO_read_end) - (stdin->_IO_read_ptr));
     debug(F101,"cmdconchk _IO_file_flags","",x);
 #else  /* _IO_file_flags */

diff --git a/ck_ssl.c b/ck_ssl.c
index 428fb7c..11caa74 100644
--- a/ck_ssl.c
+++ b/ck_ssl.c
@@ -294,21 +294,21 @@ X509_STORE_CTX *ctx;
   "Certificate issuer's certificate isn't available locally.\r\n");
                 break;
             case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
                 printf("Unable to verify leaf signature.\r\n");
                 break;
             case X509_V_ERR_CERT_REVOKED:
                 printf("Certificate revoked.\r\n");
                 break;
             default:
                 printf("Error %d while verifying certificate.\r\n",
-                       ctx->error);
+                       X509_STORE_CTX_get_error(ctx));
                 break;
             }
         }
         ok = !(ssl_verify_flag & SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
     } else {
         /* if we got all the way to the top of the tree then
          * we *can* use this certificate for a username to
          * match ... in all other cases we must not!
          */
         auth_ssl_name = saved_subject;
@@ -926,83 +926,93 @@ static unsigned char dh2048_p[]={
     0x51,0x13,0x32,0x63,
 };
 static unsigned char dh2048_g[]={
     0x02,
 };
 
 static DH *
 get_dh512()
 {
     DH *dh=NULL;
+    BIGNUM *p, *g;
 
     if ((dh=DH_new()) == NULL)
         return(NULL);
-    dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
-    dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
-    if ((dh->p == NULL) || (dh->g == NULL))
+    p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
+    g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
+    if ((p == NULL) || (g == NULL))
         return(NULL);
+    DH_set0_pqg(dh, p, NULL, g);
     return(dh);
 }
 
 static DH *
 get_dh768()
 {
     DH *dh=NULL;
+    BIGNUM *p, *g;
 
     if ((dh=DH_new()) == NULL)
         return(NULL);
-    dh->p=BN_bin2bn(dh768_p,sizeof(dh768_p),NULL);
-    dh->g=BN_bin2bn(dh768_g,sizeof(dh768_g),NULL);
-    if ((dh->p == NULL) || (dh->g == NULL))
+    p=BN_bin2bn(dh768_p,sizeof(dh768_p),NULL);
+    g=BN_bin2bn(dh768_g,sizeof(dh768_g),NULL);
+    if ((p == NULL) || (g == NULL))
         return(NULL);
+    DH_set0_pqg(dh, p, NULL, g);
     return(dh);
 }
 
 static DH *
 get_dh1024()
 {
     DH *dh=NULL;
+    BIGNUM *p, *g;
 
     if ((dh=DH_new()) == NULL)
         return(NULL);
-    dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
-    dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
-    if ((dh->p == NULL) || (dh->g == NULL))
+    p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
+    g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
+    if ((p == NULL) || (g == NULL))
         return(NULL);
+    DH_set0_pqg(dh, p, NULL, g);
     return(dh);
 }
 
 static DH *
 get_dh1536()
 {
     DH *dh=NULL;
+    BIGNUM *p, *g;
 
     if ((dh=DH_new()) == NULL)
         return(NULL);
-    dh->p=BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL);
-    dh->g=BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL);
-    if ((dh->p == NULL) || (dh->g == NULL))
+    p=BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL);
+    g=BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL);
+    if ((p == NULL) || (g == NULL))
         return(NULL);
+    DH_set0_pqg(dh, p, NULL, g);
     return(dh);
 }
 
 static DH *
 get_dh2048()
 {
     DH *dh=NULL;
+    BIGNUM *p, *g;
 
     if ((dh=DH_new()) == NULL)
         return(NULL);
-    dh->p=BN_bin2bn(dh2048_p,sizeof(dh2048_p),NULL);
-    dh->g=BN_bin2bn(dh2048_g,sizeof(dh2048_g),NULL);
-    if ((dh->p == NULL) || (dh->g == NULL))
+    p=BN_bin2bn(dh2048_p,sizeof(dh2048_p),NULL);
+    g=BN_bin2bn(dh2048_g,sizeof(dh2048_g),NULL);
+    if ((p == NULL) || (g == NULL))
         return(NULL);
+    DH_set0_pqg(dh, p, NULL, g);
     return(dh);
 }
 #endif /* NO_DH */
 
 static DH MS_CALLBACK *
 #ifdef CK_ANSIC
 tmp_dh_cb(SSL * s, int export, int keylength)
 #else /* CK_ANSIC */
 tmp_dh_cb(s,export,keylength)
 SSL *s;
@@ -1047,25 +1057,30 @@ ssl_display_comp(SSL * ssl)
 {
     if ( quiet )			/* fdc - Mon Nov 28 11:44:15 2005 */
         return;
 
     if ( !ck_ssleay_is_installed() )
         return;
 
     if (ssl == NULL)
         return;
 
-    if (ssl->expand == NULL || ssl->expand->meth == NULL)
-        printf("Compression: None\r\n");
+#ifndef OPENSSL_NO_COMP
+    const COMP_METHOD *x = SSL_get_current_expansion(ssl);
+    if (!x)
+#endif /* ifndef OPENSSL_NO_COMP */
+	printf("Compression: None\r\n");
+#ifndef OPENSSL_NO_COMP
     else {
-        printf("Compression: %s\r\n",ssl->expand->meth->name);
+        printf("Compression: %s\r\n", SSL_COMP_get_name(x));
     }
+#endif /* ifndef OPENSSL_NO_COMP */
 }
 
 int
 #ifdef CK_ANSIC
 ssl_display_connect_details(SSL * ssl_con, int server, int verbose)
 #else /* CK_ANSIC */
 ssl_display_connect_details(ssl_con,server,verbose)
 SSL *ssl_con;
 int server;
 int verbose;
@@ -1450,52 +1465,51 @@ the build.\r\n\r\n");
 #else
     /* SSL_library_init() only loads those ciphers needs for SSL  */
     /* These happen to be a similar set to those required for SSH */
     /* but they are not a complete set of ciphers provided by the */
     /* crypto library.                                            */
     SSL_library_init();
 #endif /* SSHBUILTIN */
 
 #ifdef ZLIB
     cm = COMP_zlib();
-    if (cm != NULL && cm->type != NID_undef) {
+    if (cm != NULL && COMP_get_type(cm) != NID_undef) {
         SSL_COMP_add_compression_method(0xe0, cm); /* EAY's ZLIB ID */
     }
 #endif /* ZLIB */
+#if 0 /* COMP_rle has apparently been removed in OpenSSL 1.1 */
     cm = COMP_rle();
     if (cm != NULL && cm->type != NID_undef)
         SSL_COMP_add_compression_method(0xe1, cm); /* EAY's RLE ID */
+#endif
 
     /* Ensure the Random number generator has enough entropy */
     if ( !RAND_status() ) {
         char buffer[256]="";
         char randombytes[256];
         int rc1 = -1, rc2 = 1;  /* assume failure and success */
 
         debug(F110,"ssl_once_init","!RAND_status()",0);
 
         if ( ssl_rnd_file == NULL ) {
             debug(F110,"ssl_rnd_file","ssl_rnd_file is NULL",0);
             RAND_file_name(buffer,256);
             if ( buffer[0] )
                 makestr(&ssl_rnd_file, buffer);
             else
                 makestr(&ssl_rnd_file,".rnd");
         }
         debug(F110,"ssl_rnd_file",ssl_rnd_file,0);
 
-        rc1 = RAND_egd(ssl_rnd_file);
-        debug(F111,"ssl_once_init","RAND_egd()",rc1);
-        if ( rc1 <= 0 ) {
-            rc2 = RAND_load_file(ssl_rnd_file, -1);
-            debug(F111,"ssl_once_init","RAND_load_file()",rc1);
-        }
+        rc1 = -1;
+        rc2 = RAND_load_file(ssl_rnd_file, -1);
+        debug(F111,"ssl_once_init","RAND_load_file()",rc1);
 
         if ( rc1 <= 0 && !rc2 )
         {
             time_t t = time(NULL);
             int tlen = sizeof(time_t);
             int pid = getpid();
             int plen = sizeof(int);
             int n;
 #ifndef RAND_MAX
 #define RAND_MAX 0x7FFF
@@ -1572,56 +1586,60 @@ ssl_tn_init(mode) int mode;
             tls_ctx = NULL;
         }
     }
 
     if ( (last_ssl_mode != mode) || !ssl_ctx || !tls_ctx ) {
         if ( mode == SSL_CLIENT ) {
             ssl_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_client_method());
             /* This can fail because we do not have RSA available */
             if ( !ssl_ctx ) {
                 debug(F110,"ssl_tn_init","SSLv23_client_method failed",0);
+#ifndef OPENSSL_NO_SSL3_METHOD
                 ssl_ctx=(SSL_CTX *)SSL_CTX_new(SSLv3_client_method());
+#endif /* ifndef OPENSSL_NO_SSL3_METHOD */
             }
             if ( !ssl_ctx ) {
+#ifndef OPENSSL_NO_SSL3_METHOD
                 debug(F110,"ssl_tn_init","SSLv3_client_method failed",0);
+#endif /* ifndef OPENSSL_NO_SSL3_METHOD */
                 last_ssl_mode = -1;
                 return(0);
             }
 #ifndef COMMENT
-            tls_ctx=(SSL_CTX *)SSL_CTX_new(TLSv1_client_method());
+            tls_ctx=(SSL_CTX *)SSL_CTX_new(TLS_client_method());
 #else /* COMMENT */
-            tls_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_client_method());
+            tls_ctx=(SSL_CTX *)SSL_CTX_new(TLS_client_method());
             /* This can fail because we do not have RSA available */
             if ( !tls_ctx ) {
-                debug(F110,"ssl_tn_init","SSLv23_client_method failed",0);
-                tls_ctx=(SSL_CTX *)SSL_CTX_new(SSLv3_client_method());
+                debug(F110,"ssl_tn_init","TLS_client_method failed",0);
+                tls_ctx=(SSL_CTX *)SSL_CTX_new(TLSv1_client_method());
             }
 #endif /* COMMENT */
             if ( !tls_ctx ) {
                 debug(F110,"ssl_tn_init","TLSv1_client_method failed",0);
                 last_ssl_mode = -1;
                 return(0);
             }
 #ifdef USE_CERT_CB
             SSL_CTX_set_client_cert_cb(ssl_ctx,ssl_client_cert_callback);
             SSL_CTX_set_client_cert_cb(tls_ctx,ssl_client_cert_callback);
 #endif /* USE_CERT_CB */
         } else if (mode == SSL_SERVER) {
             /* We are a server */
             ssl_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_server_method());
             /* This can fail because we do not have RSA available */
             if ( !ssl_ctx ) {
                 debug(F110,"ssl_tn_init","SSLv23_server_method failed",0);
-                ssl_ctx=(SSL_CTX *)SSL_CTX_new(SSLv3_server_method());
+                ssl_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_server_method());
             }
             if ( !ssl_ctx ) {
-                debug(F110,"ssl_tn_init","SSLv3_server_method failed",0);
+                debug(F110,"ssl_tn_init","SSLv23_server_method failed",0);
                 last_ssl_mode = -1;
                 return(0);
             }
 #ifdef COMMENT
             tls_ctx=(SSL_CTX *)SSL_CTX_new(TLSv1_server_method());
 #else /* COMMENT */
             tls_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_server_method());
             /* This can fail because we do not have RSA available */
             if ( !tls_ctx ) {
                 debug(F110,"ssl_tn_init","SSLv23_server_method failed",0);
@@ -2154,21 +2172,21 @@ ssl_http_init(hostname) char * hostname;
 
     if (!tls_http_ctx ) {
 #ifdef COMMENT
         /* too many web servers still do not support TLSv1 */
         tls_http_ctx=(SSL_CTX *)SSL_CTX_new(TLSv1_client_method());
 #else /* COMMENT */
         tls_http_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_client_method());
         /* This can fail because we do not have RSA available */
         if ( !tls_http_ctx ) {
             debug(F110,"ssl_http_init","SSLv23_client_method failed",0);
-            tls_http_ctx=(SSL_CTX *)SSL_CTX_new(SSLv3_client_method());
+            tls_http_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_client_method());
         }
 #endif /* COMMENT */
         if ( !tls_http_ctx ) {
             debug(F110,"ssl_http_init","TLSv1_client_method failed",0);
             return(0);
         }
 #ifdef USE_CERT_CB
         SSL_CTX_set_client_cert_cb(tls_http_ctx,ssl_client_cert_callback);
 #endif /* USE_CERT_CB */
     }
@@ -2568,21 +2586,21 @@ ssl_anonymous_cipher(ssl) SSL * ssl;
 #endif /* COMMENT */
 
 /*
   This one is (very much!) based on work by
   Ralf S. Engelschall <rse@engelschall.com>.
   Comments by Ralf.
 */
 int
 ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
 {
-    X509_OBJECT obj;
+    X509_OBJECT *obj;
     X509_NAME *subject = NULL;
     X509_NAME *issuer = NULL;
     X509 *xs = NULL;
     X509_CRL *crl = NULL;
     X509_REVOKED *revoked = NULL;
     X509_STORE_CTX * store_ctx = NULL;
     long serial;
     BIO *bio = NULL;
     int i, n, rc;
     char *cp;
@@ -2634,91 +2652,99 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
      *    This CRLs signature was then already verified one round before.
      *
      * This verification scheme allows a CA to revoke its own certificate as
      * well, of course.
      */
 
     /*
      * Try to retrieve a CRL corresponding to the _subject_ of
      * the current certificate in order to verify it's integrity.
      */
-    memset((char *)&obj, 0, sizeof(obj));
+    obj = X509_OBJECT_new();
+    if (!obj) {
+        X509_STORE_CTX_free(store_ctx);
+        return ok;
+    }
     X509_STORE_CTX_init(store_ctx, crl_store, NULL, NULL);
-    rc = X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, subject, &obj);
+    rc = X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, subject, obj);
     X509_STORE_CTX_cleanup(store_ctx);
-    crl = obj.data.crl;
+    crl = X509_OBJECT_get0_X509_CRL(obj);
     if (rc > 0 && crl != NULL) {
         /*
          * Verify the signature on this CRL
          */
         if (X509_CRL_verify(crl, X509_get_pubkey(xs)) <= 0) {
             fprintf(stderr, "Invalid signature on CRL!\n");
             X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
-            X509_OBJECT_free_contents(&obj);
+            X509_OBJECT_free(obj);
             X509_STORE_CTX_free(store_ctx);
             return 0;
         }
 
         /*
          * Check date of CRL to make sure it's not expired
          */
         i = X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));
         if (i == 0) {
             fprintf(stderr, "Found CRL has invalid nextUpdate field.\n");
             X509_STORE_CTX_set_error(ctx,
                                     X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
-            X509_OBJECT_free_contents(&obj);
+            X509_OBJECT_free(obj);
             X509_STORE_CTX_free(store_ctx);
             return 0;
         }
         if (i < 0) {
             fprintf(stderr,
 "Found CRL is expired - revoking all certificates until you get updated CRL.\n"
                     );
             X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_HAS_EXPIRED);
-            X509_OBJECT_free_contents(&obj);
+            X509_OBJECT_free(obj);
             X509_STORE_CTX_free(store_ctx);
             return 0;
         }
-        X509_OBJECT_free_contents(&obj);
     }
 
     /*
      * Try to retrieve a CRL corresponding to the _issuer_ of
      * the current certificate in order to check for revocation.
      */
-    memset((char *)&obj, 0, sizeof(obj));
+    X509_OBJECT_free(obj);
+    obj = X509_OBJECT_new();
+    if (!obj) {
+        X509_STORE_CTX_free(store_ctx);
+        return ok;
+    }
     X509_STORE_CTX_init(store_ctx, crl_store, NULL, NULL);
-    rc = X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, issuer, &obj);
+    rc = X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, issuer, obj);
     X509_STORE_CTX_free(store_ctx);		/* calls X509_STORE_CTX_cleanup() */
-    crl = obj.data.crl;
+    crl = X509_OBJECT_get0_X509_CRL(obj);
     if (rc > 0 && crl != NULL) {
         /*
          * Check if the current certificate is revoked by this CRL
          */
         n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
         for (i = 0; i < n; i++) {
             revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
-            if (ASN1_INTEGER_cmp(revoked->serialNumber,
+            if (ASN1_INTEGER_cmp(X509_REVOKED_get0_serialNumber(revoked),
                                  X509_get_serialNumber(xs)) == 0) {
 
-                serial = ASN1_INTEGER_get(revoked->serialNumber);
+                serial = ASN1_INTEGER_get(X509_REVOKED_get0_serialNumber(revoked));
                 cp = X509_NAME_oneline(issuer, NULL, 0);
                 free(cp);
 
                 X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
-                X509_OBJECT_free_contents(&obj);
+                X509_OBJECT_free(obj);
                 return 0;
             }
         }
-        X509_OBJECT_free_contents(&obj);
     }
+    X509_OBJECT_free(obj);
     return ok;
 }
 
 char *
 tls_userid_from_client_cert(ssl) SSL * ssl;
 {
     static char cn[256];
     static char *r = cn;
     int err;
     X509 *client_cert;
@@ -4323,34 +4349,37 @@ X509_to_user(X509 *peer_cert, char *userid, int len)
 int
 X509_userok(X509 * peer_cert, const char * userid)
 {
 #ifndef VMS
     /* check if clients cert is in "user"'s ~/.tlslogin file */
     char buf[512];
     int r = 0;
     FILE *fp;
     struct passwd *pwd;
     X509 *file_cert;
+    const ASN1_BIT_STRING *peer_sig, *file_sig;
 
     if ( peer_cert == NULL )
         return(0);
+    X509_get0_signature(&peer_sig, NULL, peer_cert);
 
     if (!(pwd = getpwnam(userid)))
        return 0;
     if (strlen(pwd->pw_dir) > 500)
        return(0);
     sprintf(buf, "%s/.tlslogin", pwd->pw_dir);
 
     if (!(fp = fopen(buf, "r")))
         return 0;
     while (!r && (file_cert = PEM_read_X509(fp, NULL, NULL, NULL))) {
-        if (!ASN1_STRING_cmp(peer_cert->signature, file_cert->signature))
+        X509_get0_signature(&file_sig, NULL, file_cert);
+        if (!ASN1_STRING_cmp(peer_sig, file_sig))
             r = 1;
         X509_free(file_cert);
     }
     fclose(fp);
     return(r);
 #else /* VMS */
     /* Need to implement an appropriate function for VMS */
     return(0);
 #endif /* VMS */
 }
diff --git a/ckcftp.c b/ckcftp.c
index 66c7940..1b57358 100644
--- a/ckcftp.c
+++ b/ckcftp.c
@@ -10189,29 +10189,29 @@ ssl_auth() {
     }
 
     /* The SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS 
      * was added to OpenSSL 0.9.6e and 0.9.7.  It does not exist in previous
      * versions
      */
 #ifndef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
 #define SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS 0L
 #endif
     if (auth_type && !strcmp(auth_type,"TLS")) {
-        ssl_ftp_ctx=SSL_CTX_new(SSLv3_client_method());
+        ssl_ftp_ctx=SSL_CTX_new(TLS_client_method());
         if (!ssl_ftp_ctx)
           return(0);
         SSL_CTX_set_options(ssl_ftp_ctx,
                             SSL_OP_SINGLE_DH_USE|SSL_OP_EPHEMERAL_RSA
                             );
     } else {
         ssl_ftp_ctx = SSL_CTX_new(ftp_bug_use_ssl_v2 ? SSLv23_client_method() : 
-                                  SSLv3_client_method());
+                                  TLS_client_method());
         if (!ssl_ftp_ctx)
           return(0);
         SSL_CTX_set_options(ssl_ftp_ctx,
                             (ftp_bug_use_ssl_v2 ? 0 : SSL_OP_NO_SSLv2)|
                             SSL_OP_SINGLE_DH_USE|SSL_OP_EPHEMERAL_RSA
                             );
     }
     SSL_CTX_set_default_passwd_cb(ssl_ftp_ctx,
                                   (pem_password_cb *)ssl_passwd_callback);
     SSL_CTX_set_info_callback(ssl_ftp_ctx,ssl_client_info_callback);
diff --git a/ckcpro.c b/ckcpro.c
index 3c51b6b..499ec46 100644
--- a/ckcpro.c
+++ b/ckcpro.c
@@ -1,31 +1,31 @@
 
 /* WARNING -- This C source program generated by Wart preprocessor. */
 /* Do not edit this file; edit the Wart-format source file instead, */
 /* and then run it through Wart to produce a new C source file.     */
 
 /* Wart Version Info: */
 char *wartv = "Wart Version 2.14, 10 Nov 1999";
 
 char *protv =                                                     /* -*-C-*- */
-"C-Kermit Protocol Module 8.0.160, 12 Aug 2007";
+"C-Kermit Protocol Module 9.0.160, 16 Oct 2009";
 
 int kactive = 0;			/* Kermit protocol is active */
 
 #define PKTZEROHACK
 
 /* C K C P R O  -- C-Kermit Protocol Module, in Wart preprocessor notation. */
 /*
   Author: Frank da Cruz <fdc@columbia.edu>,
   Columbia University Academic Information Systems, New York City.
 
-  Copyright (C) 1985, 2007,
+  Copyright (C) 1985, 2009,
     Trustees of Columbia University in the City of New York.
     All rights reserved.  See the C-Kermit COPYING.TXT file or the
     copyright text in the ckcmai.c module for disclaimer and permissions.
 */
 #ifndef NOXFER
 #include "ckcsym.h"
 #include "ckcdeb.h"
 #include "ckcasc.h"
 #include "ckcker.h"
 #ifdef OS2
@@ -162,20 +162,21 @@ _PROTOTYP( int cmdsrc, (void) );
 #endif /* CK_ENCRYPTION */
 #endif /* TNCODE */
 
 #ifdef TCPSOCKET
 #ifndef NOLISTEN
   extern int tcpsrfd;
 #endif /* NOLISTEN */
 #endif /* TCPSOCKET */
 
   extern int cxseen, czseen, server, srvdis, local, displa, bctu, bctr, bctl;
+  extern int bctf;
   extern int quiet, tsecs, parity, backgrd, nakstate, atcapu, wslotn, winlo;
   extern int wslots, success, xitsta, rprintf, discard, cdtimo, keep, fdispla;
   extern int timef, stdinf, rscapu, sendmode, epktflg, epktrcvd, epktsent;
   extern int binary, fncnv;
   extern long speed, ffc, crc16, calibrate, dest;
 #ifdef COMMENT
   extern char *TYPCMD, *DIRCMD, *DIRCM2;
 #endif /* COMMENT */
 #ifndef OS2
   extern char *SPACMD, *SPACM2, *WHOCMD;
@@ -497,31 +498,36 @@ case 10:
     justone = x;
 #ifdef IKSDB
     if (ikdbopen) slotstate(what, "SERVER", "", "");
 #endif /* IKSDB */
 }
     break;
 case 11:
     {
     int b1 = 0, b2 = 0;
     if (!data) TINIT;			/* "ABEND" -- Tell other side. */
+
+    if (!bctf) {		     /* Block check 3 forced on all packets */
 #ifndef pdp11
-    if (epktflg) {			/* If because of E-PACKET command */
-	b1 = bctl; b2 = bctu;		/* Save block check type */
-	bctl = bctu = 1;		/* set it to 1 */
-    }
+	if (epktflg) {			/* If because of E-PACKET command */
+	    b1 = bctl; b2 = bctu;	/* Save block check type */
+	    bctl = bctu = 1;		/* set it to 1 */
+	}
 #endif /* pdp11 */
+    }
     errpkt((CHAR *)"User cancelled");	/* Send the packet */
+    if (!bctf) {		     /* Block check 3 forced on all packets */
 #ifndef pdp11
-    if (epktflg) {			/* Restore the block check */
-	epktflg = 0;
-	bctl = b1; bctu = b2;
+	if (epktflg) {			/* Restore the block check */
+	    epktflg = 0;
+	    bctl = b1; bctu = b2;
+	}
     }
 #endif /* pdp11 */
     success = 0;
     return(0);				/* Return from protocol. */
 }
     break;
 case 12:
     {		/* Receive Send-Init packet. */
     rc = rcv_s_pkt();
     cancel = 0;				/* Reset cancellation counter */
@@ -938,21 +944,21 @@ case 31:
 		} else {		/* not OK */
 		    p = zgtdir();
 		    if (!p) p = "";
 		    success = (*p) ? 1 : 0;
 		    ack1((CHAR *)p);	/* ACK with new directory name */
 		    success = 1;
 		    RESUME;		/* wait for next server command */
 		}
 	    }
 	} else {			/* User doesn't want message */
-	    p =zgtdir();
+	    p = zgtdir();
 	    if (!p) p = "";
 	    success = (*p) ? 1 : 0;
 	    ack1((CHAR *)p);
 	    success = 1;
 	    RESUME;			/* Wait for next server command */
 	}
     }
 #endif /* NOSERVER */
 }
     break;
@@ -1122,21 +1128,21 @@ case 37:
 	RESUME;
     } else {
 	ack();				/* Acknowledge */
 	success = 1;
 	msleep(750);			/* Give the ACK time to get out */
 	if (local)
 	  ttres();			/* Reset the terminal */
 	xxscreen(SCR_TC,0,0L,"");	/* Display */
 	doclean(1);			/* Clean up files, etc */
 #ifdef DEBUG
-	debug(F100,"C-Kermit BYE - Loggin out...","",0);
+	debug(F100,"C-Kermit BYE - Logging out...","",0);
 	zclose(ZDFILE);
 #endif /* DEBUG */
 #ifdef IKSD
 #ifdef CK_LOGIN
 	if (inserver)
 	  ckxlogout();
 	else
 #endif /* CK_LOGIN */
 #endif /* IKSD */
 #ifdef TCPSOCKET
@@ -1766,22 +1772,28 @@ case 61:
 	ack();
 	BEGIN rfile;
     }
 #endif /* COHERENT */
 }
     break;
 case 62:
     {				/* ACK for Send-Init */
     spar(rdatap);			/* set parameters from it */
     cancel = 0;
-    bctu = bctr;			/* switch to agreed-upon block check */
-    bctl = (bctu == 4) ? 2 : bctu;	/* Set block-check length */
+    if (bctf) {
+	bctu = 3;
+	bctl = 3;
+    } else {
+	bctu = bctr;			/* switch to agreed-upon block check */
+	bctl = (bctu == 4) ? 2 : bctu;	/* Set block-check length */
+    }
+
 #ifdef CK_RESEND
     if ((sendmode == SM_RESEND) && (!atcapu || !rscapu)) { /* RESEND */
 	errpkt((CHAR *) "RESEND capabilities not negotiated");
 	RESUME;
     } else {
 #endif /* CK_RESEND */
 	what = W_SEND;			/* Remember we're sending */
 	lastxfer = W_SEND;
 	x = sfile(xflg);		/* Send X or F header packet */
 	cancel = 0;			/* Reset cancellation counter */
@@ -2919,22 +2931,27 @@ rcv_s_pkt() {
 		    debug(F100,"receive zchdir ok","",0);
 		    ckstrncpy(savdir,s,TMPDIRLEN);
 		    f_tmpdir = 1;	/* Remember that we did this */
 		} else
 		  debug(F100,"receive zchdir failed","",0);
 	    }
 	}
 #endif /* CK_TMPDIR */
 	nakstate = 1;			/* Can send NAKs from here. */
 	rinit(rdatap);			/* Set parameters */
-	bctu = bctr;			/* Switch to agreed-upon block check */
-	bctl = (bctu == 4) ? 2 : bctu;	/* Set block-check length */
+	if (bctf) {
+	    bctu = 3;
+	    bctl = 3;
+	} else {
+	    bctu = bctr;	       /* switch to agreed-upon block check */
+	    bctl = (bctu == 4) ? 2 : bctu; /* Set block-check length */
+	}
 	what = W_RECV;			/* Remember we're receiving */
 	lastxfer = W_RECV;
 	resetc();			/* Reset counters */
 	rtimer();			/* Reset timer */
 #ifdef GFTIMER
 	rftimer();
 #endif /* GFTIMER */
 	streamon();
 	BEGIN rfile;			/* Go into receive-file state */
     }
diff --git a/ckuath.c b/ckuath.c
index ea9bc7d..0f53a33 100644
--- a/ckuath.c
+++ b/ckuath.c
@@ -4516,21 +4516,21 @@ k5_get_ccache(k5_context, p_ccache, cc_name)
         } else {
             /* Make sure GSSAPI sees the same cache we are using */
             char buf[128];
             ckmakmsg((char *)buf,128,"KRB5CCNAME=",cc_tmp,NULL,NULL);
             putenv(buf);
         }
     } else
 #endif /* HEIMDAL */
     {
         if ((r = krb5_cc_default(k5_context, p_ccache))) {
-            com_err("k5_get_ccache",r,"while getting default ccache");
+            /* com_err("k5_get_ccache",r,"while getting default ccache"); */
         }
     }
     /* do not set krb5_errno/krb5_errmsg here since the value returned */
     /* is being passed internally within the krb5 functions.           */
     return(r);
 }
 
 
 char *
 ck_krb5_realmofhost(char *host)
@@ -10920,21 +10920,21 @@ ck_krb5_get_cc_name()
         return(cc_name);
 
     p = getenv("KRB5CCNAME");
     if ( !p ) {
         code = krb5_init_context(&kcontext);
         if (code) {
             com_err("ck_krb5_get_cc_name",code,"while init_context");
             return(cc_name);
         }
         if ((code = krb5_cc_default(kcontext, &ccache))) {
-            com_err("ck_krb5_get_cc_name",code,"while getting default ccache");
+            /* com_err("ck_krb5_get_cc_name",code,"while getting default ccache"); */
             goto exit_k5_get_cc;
         }
 
         ckmakmsg(cc_name,sizeof(cc_name),
                  (char *)krb5_cc_get_type(kcontext,ccache),":",
                  (char *)krb5_cc_get_name(kcontext,ccache),NULL);
     } else {
         ckstrncpy(cc_name,p,CKMAXPATH);
     }
 
diff --git a/ckuus3.c b/ckuus3.c
index 5887b34..e7e10d0 100644
--- a/ckuus3.c
+++ b/ckuus3.c
@@ -10299,31 +10299,33 @@ case XYCARR:                            /* CARRIER-WATCH */
                   break;
                 case TN_EN_START:
                   if ((z = cmcfm()) < 0)
                     return(z);
 #ifdef CK_APC
                   /* Don't let this be set remotely */
                   if (apcactive == APC_LOCAL ||
                       apcactive == APC_REMOTE && !(apcstatus & APC_UNCH))
                     return(success = 0);
 #endif /* CK_APC */
+		  void ck_tn_enc_start();
                   ck_tn_enc_start();
                   break;
                 case TN_EN_STOP:
                   if ((z = cmcfm()) < 0)
                     return(z);
 #ifdef CK_APC
                   /* Don't let this be set remotely */
                   if (apcactive == APC_LOCAL ||
                       apcactive == APC_REMOTE && !(apcstatus & APC_UNCH))
                     return(success = 0);
 #endif /* CK_APC */
+		  void ck_tn_enc_stop();
                   ck_tn_enc_stop();
                   break;
                 default:
                   if ((z = cmcfm()) < 0)
                     return(z);
                   TELOPT_DEF_C_ME_MODE(TELOPT_ENCRYPTION) = y;
                   TELOPT_DEF_C_U_MODE(TELOPT_ENCRYPTION) = y;
                   TELOPT_DEF_S_ME_MODE(TELOPT_ENCRYPTION) = y;
                   TELOPT_DEF_S_U_MODE(TELOPT_ENCRYPTION) = y;
               }

diff --git a/ckuusr.c b/ckuusr.c
index 3b77fe6..4a756b2 100644
--- a/ckuusr.c
+++ b/ckuusr.c
@@ -86,20 +86,21 @@ char *userv = "User Interface 9.0.299, 9 Jun 2011";
 #ifdef MULTINET
 #define MULTINET_OLD_STYLE		/* Leave select prototype undefined */
 #endif /* MULTINET */
 
 #include "ckcdeb.h"
 #include "ckcasc.h"
 #include "ckcker.h"
 #include "ckcnet.h"			/* Network symbols */
 #include "ckuusr.h"
 #include "ckcxla.h"
+#include "ckuath.h"
 
 int g_fncact = -1;			/* Needed for NOICP builds */
 int noinit = 0;				/* Flag for skipping init file */
 int nscanfile = SCANFILEBUF;
 
 int rcdactive = 0;			/* RCD active */
 int keepallchars = 0;			/* See cmfld() */
 
 int locus = 1;				/* Current LOCUS is LOCAL */
 #ifdef OS2

diff --git a/ckuusx.c b/ckuusx.c
index d332bed..1b1fa4d 100644
--- a/ckuusx.c
+++ b/ckuusx.c
@@ -37,20 +37,23 @@
 #define NOHTERMCAP
 #else
 #ifdef __bsdi__
 #define NOHTERMCAP
 #else
 #ifdef OPENBSD
 #define NOHTERMCAP
 #else
 #ifdef MACOSX
 #define NOHTERMCAP
+#ifdef CK_NCURSES
+#include <ncurses.h>
+#endif /* ifdef CK_NCURSES */
 #endif /* MACOSX */
 #endif /* OPENBSD */
 #endif /* __bsdi__ */
 #endif /* BSD44 */
 #endif /* NOTERMCAP */
 #endif /* NOHTERMCAP */
 
 #ifndef NOTERMCAP
 #ifdef BSD44
 #ifndef NOHTERMCAP

diff --git a/ckuusx.c b/ckuusx.c
index 1b1fa4d..b6d4274 100644
--- a/ckuusx.c
+++ b/ckuusx.c
@@ -59,21 +59,25 @@
 #ifndef NOHTERMCAP
 #include <termcap.h>
 #endif /* NOHTERMCAP */
 #endif /* BSD44 */
 #else  /* !BSD44 */
 #ifdef linux
 #include <term.h>
 #endif /* linux */
 #endif /* NOTERMCAP */
 
+#ifdef CK_NCURSES
+#include <term.h>
+#endif /* ifdef CK_NCURSES */
 #ifdef OS2
+
 #include <string.h>
 _PROTOTYP(char * os2_gethostname, (void));
 #define getpid _getpid
 #endif /* OS2 */
 #ifdef BSD44
 #include <errno.h>
 #endif /* BSD44 */
 
 extern xx_strp xxstring;
 
diff --git a/ckucns.c b/ckucns.c
index 337197c..8c14b38 100644
--- a/ckucns.c
+++ b/ckucns.c
@@ -188,20 +188,21 @@ extern int protocol;
 extern int autodl;			/* Auto download */
 #endif /* NOXFER */
 
 #ifdef CK_AUTODL
 extern CHAR ksbuf[];
 extern CHAR stchr;
 extern int kstartactive;
 #endif /* CK_AUTODL */
 
 #ifdef CK_ENCRYPTION
+#include "ckuath.h"
 extern int me_auth;
 #endif /* CK_ENCRYPTION */
 
 #ifdef CK_XYZ
 #ifdef XYZ_INTERNAL
 static int zmdlok = 1;			/* Zmodem autodownloads available */
 #else
 static int zmdlok = 0;			/* Depends on external protocol def */
 #endif /* XYZ_INTERNAL */
 #else
diff --git a/ckutio.c b/ckutio.c
index 05564de..47802a4 100644
--- a/ckutio.c
+++ b/ckutio.c
@@ -365,20 +365,24 @@ char unm_ver[CK_SYSNMLN+1] = { '\0', '\0' };
 #ifdef USE_UU_LOCK
 #ifdef __FreeBSD__
 #include <libutil.h>			/* FreeBSD */
 #else
 #include <util.h>			/* OpenBSD */
 #endif /* HAVE_LOCKDEV */
 #endif /* __FreeBSD */
 #endif /* USE_UU_LOCK */
 #else  /* USETTYLOCK */
 
+#ifdef MACOSX
+#include <util.h>
+#endif /* MACOSX */
+
 /* Name of UUCP tty device lockfile */
 
 #ifdef LINUXFSSTND
 #ifndef HDBUUCP
 #define HDBUUCP
 #endif /* HDBUUCP */
 #endif /* LINUXFSSTND */
 
 #ifdef ACUCNTRL
 #define LCKDIR

diff --git a/ckufio.c b/ckufio.c
index b5bfaae..25194e5 100644
--- a/ckufio.c
+++ b/ckufio.c
@@ -34,20 +34,21 @@ char *ckzv = "UNIX File support, 9.0.216, 20 Aug 2011";
 */
 /* Include Files */
 
 #ifdef MINIX2
 #define _MINIX
 #endif /* MINIX2 */
 
 #include "ckcsym.h"
 #include "ckcdeb.h"
 #include "ckcasc.h"
+#include "ckuath.h"
 
 #ifndef NOCSETS
 #include "ckcxla.h"
 #endif /* NOCSETS */
 
 /* To avoid pulling in all of ckuusr.h so we copy the few needed prototypes */
 
 struct mtab {				/* Macro table, like keyword table */
     char *kwd;				/* But with pointers for vals */
     char *mval;				/* instead of ints. */
diff --git a/ckupty.c b/ckupty.c
index 9906555..b6d2264 100644
--- a/ckupty.c
+++ b/ckupty.c
@@ -60,20 +60,24 @@ char *ckptyv = "Pseudoterminal support, 9.0.101, 13 Jun 2011";
 #ifndef NETPTY				/* Selector for PTY support */
 
 char * ptyver = "No PTY support";
 
 #else  /* (rest of this module...) */
 
 char * ptyver = "PTY support 8.0.016, 22 Aug 2007";
 
 /* These will no doubt need adjustment... */
 
+#ifdef MACOSX
+#include <util.h>
+#endif
+
 #ifndef NEXT
 #define HAVE_SETSID
 #endif /* NEXT */
 #define HAVE_KILLPG
 #define HAVE_TTYNAME
 #define HAVE_WAITPID
 
 #ifdef SUNOS41
 #define BSD44ORPOSIX
 #endif	/* SUNOS41 */

diff --git a/ckctel.c b/ckctel.c
index e9f1295..2695898 100644
--- a/ckctel.c
+++ b/ckctel.c
@@ -4309,20 +4309,21 @@ extern char * trmbuf;                   /* Real curses */
 
 #ifdef CK_ENCRYPTION
 static int
 tn_no_encrypt()
 {
     /* Prevent Encryption from being negotiated */
     TELOPT_ME_MODE(TELOPT_ENCRYPTION) = TN_NG_RF;
     TELOPT_U_MODE(TELOPT_ENCRYPTION) = TN_NG_RF;
 
     /* Cancel any negotiation that might have started */
+    void ck_tn_enc_stop();
     ck_tn_enc_stop();
 
     if (TELOPT_ME(TELOPT_ENCRYPTION) ||
          TELOPT_UNANSWERED_WILL(TELOPT_ENCRYPTION)) {
         TELOPT_ME(TELOPT_ENCRYPTION) = 0;
         if (tn_sopt(WONT,TELOPT_ENCRYPTION) < 0)
             return(-1);
         TELOPT_UNANSWERED_WONT(TELOPT_ENCRYPTION) = 1;
     }
     if (TELOPT_U(TELOPT_ENCRYPTION) ||
@@ -4703,20 +4704,21 @@ tn_xdoop(z, echo, fn) CHAR z; int echo; int (*fn)();
 #ifdef CK_ENCRYPTION
                 if (sstelnet) {
                     if (tn_no_encrypt()<0)
                         return(-1);
                 }
 #endif /* CK_ENCRYPTION */
                 break;
 #endif /* CK_AUTHENTICATION */
 #ifdef CK_ENCRYPTION
               case TELOPT_ENCRYPTION:
+		void ck_tn_enc_stop();
                 ck_tn_enc_stop();
                 break;
 #endif /* CK_ENCRYPTION */
 #ifdef IKS_OPTION
               case TELOPT_KERMIT:
                 TELOPT_SB(x).kermit.u_start = 0;
                 TELOPT_SB(x).kermit.me_req_start = 0;
                 TELOPT_SB(x).kermit.me_req_stop = 0;
                 break;
 #endif /* IKS_OPTION */
@@ -5036,20 +5038,21 @@ tn_xdoop(z, echo, fn) CHAR z; int echo; int (*fn)();
 #ifdef CK_ENCRYPTION
                 if (!sstelnet) {
                     if (tn_no_encrypt()<0)
                         return(-1);
                 }
 #endif /* CK_ENCRYPTION */
                 break;
 #endif /* CK_AUTHENTICATION */
               case TELOPT_ENCRYPTION:
 #ifdef CK_ENCRYPTION
+		void ck_tn_enc_stop();
                 ck_tn_enc_stop();
 #endif /* CK_ENCRYPTION */
                 break;
               case TELOPT_KERMIT:
 #ifdef IKS_OPTION
                 TELOPT_SB(x).kermit.me_start = 0;
 #endif /* IKS_OPTION */
                 break;
               default:
                 break;
diff --git a/ckutio.c b/ckutio.c
index 47802a4..f336f67 100644
--- a/ckutio.c
+++ b/ckutio.c
@@ -14658,20 +14658,23 @@ ttptycmd(s) char *s; {
 
     debug(F100,"ttptycmd OPENPTY","",0);
     if (tcgetattr(0, &term) == -1) {	/* Get controlling terminal's modes */
 	perror("tcgetattr");
 	return(0);
     }
     if (ioctl(0, TIOCGWINSZ, (char *) &twin) == -1) { /* and window size */
 	perror("ioctl TIOCGWINSZ");
 	return(0);
     }
+#ifdef MACOSX
+    int openpty(int *aprimary, int *areplica, char *name, struct termios *termp, struct winsize *winp);
+#endif
     if (openpty(&masterfd, &slavefd, NULL, NULL, NULL) == -1) {
 	debug(F101,"ttptycmd openpty failed errno","",errno);
 	perror("opentpy");
 	return(0);
     }
     debug(F101,"ttptycmd openpty masterfd","",masterfd);
     debug(F101,"ttptycmd openpty slavefd","",slavefd);
     pty_master_fd = masterfd;
     pty_slave_fd = slavefd;
     debug(F101,"ttptycmd openpty pty_master_fd","",pty_master_fd);

diff --git a/ckctel.c b/ckctel.c
index 2695898..3ce56a0 100644
--- a/ckctel.c
+++ b/ckctel.c
@@ -4704,21 +4704,20 @@ tn_xdoop(z, echo, fn) CHAR z; int echo; int (*fn)();
 #ifdef CK_ENCRYPTION
                 if (sstelnet) {
                     if (tn_no_encrypt()<0)
                         return(-1);
                 }
 #endif /* CK_ENCRYPTION */
                 break;
 #endif /* CK_AUTHENTICATION */
 #ifdef CK_ENCRYPTION
               case TELOPT_ENCRYPTION:
-		void ck_tn_enc_stop();
                 ck_tn_enc_stop();
                 break;
 #endif /* CK_ENCRYPTION */
 #ifdef IKS_OPTION
               case TELOPT_KERMIT:
                 TELOPT_SB(x).kermit.u_start = 0;
                 TELOPT_SB(x).kermit.me_req_start = 0;
                 TELOPT_SB(x).kermit.me_req_stop = 0;
                 break;
 #endif /* IKS_OPTION */
@@ -5038,21 +5037,20 @@ tn_xdoop(z, echo, fn) CHAR z; int echo; int (*fn)();
 #ifdef CK_ENCRYPTION
                 if (!sstelnet) {
                     if (tn_no_encrypt()<0)
                         return(-1);
                 }
 #endif /* CK_ENCRYPTION */
                 break;
 #endif /* CK_AUTHENTICATION */
               case TELOPT_ENCRYPTION:
 #ifdef CK_ENCRYPTION
-		void ck_tn_enc_stop();
                 ck_tn_enc_stop();
 #endif /* CK_ENCRYPTION */
                 break;
               case TELOPT_KERMIT:
 #ifdef IKS_OPTION
                 TELOPT_SB(x).kermit.me_start = 0;
 #endif /* IKS_OPTION */
                 break;
               default:
                 break;
diff --git a/makefile b/makefile
index 9efe262..d2ca54a 100644
--- a/makefile
+++ b/makefile
@@ -2127,21 +2127,21 @@ macosx+krb5+openssl macosx10.5+krb5+openssl macosx10.6+krb5+openssl:
 	then HAVE_KRB5CONFIG=`/usr/bin/krb5-config --libs krb5 gssapi` ; \
 	else HAVE_KRB5CONFIG='-lgssapi_krb5 -lkrb5 -lk5crypto \
 	-lcom_err -lresolv' ; fi; \
 	$(MAKE) CC=$(CC) CC2=$(CC2) xermit KTARGET=$${KTARGET:-$(@)} \
 	"CFLAGS= -DMACOSX10 $$IS_MACOSX103 -DCK_NCURSES -DTCPSOCKET \
 	-DUSE_STRERROR -DUSE_NAMESER_COMPAT -DNOCHECKOVERFLOW -DFNFLOAT \
 	-DCKHTTP -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 $$HAVE_UTMPX \
 	-DNODCLINITGROUPS -DCK_AUTHENTICATION -DCK_KERBEROS -DKRB5 -DZLIB \
 	-DCK_ENCRYPTION -DCK_CAST -DCK_SSL -DOPENSSL_098 $$HAVE_DES \
 	-DNOUUCP -DHERALD=\"\\\" $${MACOSNAME} $${MACOSV}\\\"\" \
-	-DCKCPU=\"\\\"$${MACCPU}\\\"\" \
+	-Wno-implicit-function-declaration -DCKCPU=\"\\\"$${MACCPU}\\\"\" \
 	-funsigned-char -O $(KFLAGS)" \
 	"LIBS= $$HAVE_KRB5CONFIG -lssl -lcrypto -lpam -lncurses $(LIBS)"
 
 # End of Mac OS X Section
 
 #Acorn RISCiX, based on ...
 #Berkeley Unix 4.2 or 4.3 with lock directory /usr/spool/uucp/LCK/LCK..ttyxx,
 #but without acucntrl program
 riscix:
 	@echo Making C-Kermit $(CKVER) for RISCiX, /usr/spool/uucp/LCK..ttyxx

diff --git a/makefile b/makefile
index e8c839c..3b65a9a 100644
--- a/makefile
+++ b/makefile
@@ -2129,21 +2129,21 @@ macosx+krb5+openssl macosx10.5+krb5+openssl macosx10.6+krb5+openssl:
 	-lcom_err -lresolv' ; fi; \
 	$(MAKE) CC=$(CC) CC2=$(CC2) xermit KTARGET=$${KTARGET:-$(@)} \
 	"CFLAGS= -DMACOSX10 $$IS_MACOSX103 -DCK_NCURSES -DTCPSOCKET \
 	-DUSE_STRERROR -DUSE_NAMESER_COMPAT -DNOCHECKOVERFLOW -DFNFLOAT \
 	-DCKHTTP -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 $$HAVE_UTMPX \
 	-DNODCLINITGROUPS -DCK_AUTHENTICATION -DCK_KERBEROS -DKRB5 -DZLIB \
 	-DCK_ENCRYPTION -DCK_CAST -DCK_SSL -DOPENSSL_098 $$HAVE_DES \
 	-DNOUUCP -DHERALD=\"\\\" $${MACOSNAME} $${MACOSV}\\\"\" \
 	-Wno-implicit-function-declaration -DCKCPU=\"\\\"$${MACCPU}\\\"\" \
 	-funsigned-char -O $(KFLAGS)" \
-	"LIBS= $$HAVE_KRB5CONFIG -lssl -lcrypto -lpam -lncurses $(LIBS)"
+	"LIBS= $$HAVE_KRB5CONFIG -lssl -lcrypto -lpam -lncurses -lresolv $(LIBS)"
 
 # End of Mac OS X Section
 
 #Acorn RISCiX, based on ...
 #Berkeley Unix 4.2 or 4.3 with lock directory /usr/spool/uucp/LCK/LCK..ttyxx,
 #but without acucntrl program
 riscix:
 	@echo Making C-Kermit $(CKVER) for RISCiX, /usr/spool/uucp/LCK..ttyxx
 	$(MAKE) wermit KTARGET=$${KTARGET:-$(@)} \
 		"CFLAGS= -DBSD42 -DBSD4 -DRISCIX -DNOCSETS \

diff --git a/ckctel.c b/ckctel.c
index 3ce56a0..ce1a1cc 100644
--- a/ckctel.c
+++ b/ckctel.c
@@ -4309,21 +4309,23 @@ extern char * trmbuf;                   /* Real curses */
 
 #ifdef CK_ENCRYPTION
 static int
 tn_no_encrypt()
 {
     /* Prevent Encryption from being negotiated */
     TELOPT_ME_MODE(TELOPT_ENCRYPTION) = TN_NG_RF;
     TELOPT_U_MODE(TELOPT_ENCRYPTION) = TN_NG_RF;
 
     /* Cancel any negotiation that might have started */
+#ifdef MACOSX
     void ck_tn_enc_stop();
+#endif
     ck_tn_enc_stop();
 
     if (TELOPT_ME(TELOPT_ENCRYPTION) ||
          TELOPT_UNANSWERED_WILL(TELOPT_ENCRYPTION)) {
         TELOPT_ME(TELOPT_ENCRYPTION) = 0;
         if (tn_sopt(WONT,TELOPT_ENCRYPTION) < 0)
             return(-1);
         TELOPT_UNANSWERED_WONT(TELOPT_ENCRYPTION) = 1;
     }
     if (TELOPT_U(TELOPT_ENCRYPTION) ||

diff --git a/makefile b/makefile
index 3b65a9a..bfe71f8 100644
--- a/makefile
+++ b/makefile
@@ -6295,33 +6295,33 @@ linux+krb5+ssl linux+krb5+openssl:
 	esac; \
 	HAVE_DES=''; \
 	DES_LIB=''; \
 	if ls /usr/lib/libdes* > /dev/null 2> /dev/null || \
 	   ls $(SSLLIB)/libdes* > /dev/null 2> /dev/null; then \
 	      DES_LIB='-ldes425'; \
 	      HAVE_DES='-DCK_DES -DLIBDES'; \
 	      echo "HAVE DES"; \
 	   else echo "NO DES"; \
 	fi; \
-	K5CRYPTO=''; \
+	K5CRYPTO='-lk5crypto'; \
         if ls /lib/libk5crypto* > /dev/null 2> /dev/null; then \
                 K5CRYPTO='-lk5crypto'; \
 	else if ls /usr/lib/libk5crypto* > /dev/null 2> /dev/null; then \
 		K5CRYPTO='-lk5crypto'; \
         else if ls /usr/lib64/libk5crypto* > /dev/null 2> /dev/null; then \
                 K5CRYPTO='-lk5crypto'; \
 	fi; fi; fi; \
-	COM_ERR=''; \
+	COM_ERR='-lcom_err'; \
 	if ls /lib/libcom_err* > /dev/null 2> /dev/null; then \
 		COM_ERR='-lcom_err'; \
 	fi; \
-	GSSAPILIB='-lgssapi'; \
+	GSSAPILIB='-lgssapi_krb5'; \
 	if ls /lib/libgssapi_krb5* > /dev/null 2> /dev/null; then \
 		GSSAPILIB='-lgssapi_krb5'; \
 	else if ls /usr/lib/libgssapi_krb5* > /dev/null 2> /dev/null; then \
 		GSSAPILIB='-lgssapi_krb5'; \
 	else K5DIR=`echo $(K5LIB) | sed 's|-L||'`; \
 		if ls $$K5DIR/libgssapi_krb5* > /dev/null 2> /dev/null; then \
 			GSSAPILIB='-lgssapi_krb5'; \
 	fi; fi; fi; \
 	$(MAKE) linux KTARGET=$${KTARGET:-$(@)} "CC = gcc" "CC2 = gcc" \
 	"KFLAGS= -DCK_AUTHENTICATION -DCK_KERBEROS -DKRB5 \

diff --git a/makefile b/makefile
index bfe71f8..b5ef2b7 100644
--- a/makefile
+++ b/makefile
@@ -6322,21 +6322,21 @@ linux+krb5+ssl linux+krb5+openssl:
 	else K5DIR=`echo $(K5LIB) | sed 's|-L||'`; \
 		if ls $$K5DIR/libgssapi_krb5* > /dev/null 2> /dev/null; then \
 			GSSAPILIB='-lgssapi_krb5'; \
 	fi; fi; fi; \
 	$(MAKE) linux KTARGET=$${KTARGET:-$(@)} "CC = gcc" "CC2 = gcc" \
 	"KFLAGS= -DCK_AUTHENTICATION -DCK_KERBEROS -DKRB5 \
 	-DCK_SSL -DCK_PAM -DZLIB -DCK_SHADOW $$OPENSSLOPTION $(SSLINC) \
 	-DCK_ENCRYPTION $$HAVE_DES $(K5INC) $(K5INC)/krb5 \
 	-I/usr/include/et $(KFLAGS)" "LNKFLAGS = $(LNKFLAGS)" \
 	"LIBS = $(K5LIB) $(SSLLIB) -lssl $$DES_LIB -lpam -lz \
-	-lcrypto $$GSSAPILIB -lkrb5 $$K5CRYPTO $$COM_ERR $(LIBS)" ; \
+	-lcrypto $$GSSAPILIB -lkrb5 $$K5CRYPTO $$COM_ERR -lncurses $(LIBS)" ; \
 	if [ ! -f ./wermit ] || [ ./ckcmai.o -nt ./wermit ] ; then \
 		echo ""; \
 		echo "If build failed try:"; \
 		echo ""; \
 		echo "  make clean ; make $${KTARGET:-$(@)} KFLAGS=-UCK_DES"; \
 		echo ""; \
 	fi
 
 # ::BEGIN_OLD_LINUX_TARGETS::
 
