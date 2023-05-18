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
    depends_on "krb5"
    depends_on "linux-pam"
  end

  # Apply patches to fix build failures on modern systems and to support OpenSSL 1.1+
  # These issues will be fixed in next release: https://www.kermitproject.org/ckupdates.html
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
@@ -304 +304 @@ X509_STORE_CTX *ctx;
-                       ctx->error);
+                       X509_STORE_CTX_get_error(ctx));
@@ -935,0 +936 @@ get_dh512()
+    BIGNUM *p, *g;
@@ -939,3 +940,3 @@ get_dh512()
-    dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
-    dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
-    if ((dh->p == NULL) || (dh->g == NULL))
+    p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
+    g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
+    if ((p == NULL) || (g == NULL))
@@ -942,0 +944 @@ get_dh512()
+    DH_set0_pqg(dh, p, NULL, g);
@@ -949,0 +952 @@ get_dh768()
+    BIGNUM *p, *g;
@@ -953,3 +956,3 @@ get_dh768()
-    dh->p=BN_bin2bn(dh768_p,sizeof(dh768_p),NULL);
-    dh->g=BN_bin2bn(dh768_g,sizeof(dh768_g),NULL);
-    if ((dh->p == NULL) || (dh->g == NULL))
+    p=BN_bin2bn(dh768_p,sizeof(dh768_p),NULL);
+    g=BN_bin2bn(dh768_g,sizeof(dh768_g),NULL);
+    if ((p == NULL) || (g == NULL))
@@ -956,0 +960 @@ get_dh768()
+    DH_set0_pqg(dh, p, NULL, g);
@@ -963,0 +968 @@ get_dh1024()
+    BIGNUM *p, *g;
@@ -967,3 +972,3 @@ get_dh1024()
-    dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
-    dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
-    if ((dh->p == NULL) || (dh->g == NULL))
+    p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
+    g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
+    if ((p == NULL) || (g == NULL))
@@ -970,0 +976 @@ get_dh1024()
+    DH_set0_pqg(dh, p, NULL, g);
@@ -977,0 +984 @@ get_dh1536()
+    BIGNUM *p, *g;
@@ -981,3 +988,3 @@ get_dh1536()
-    dh->p=BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL);
-    dh->g=BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL);
-    if ((dh->p == NULL) || (dh->g == NULL))
+    p=BN_bin2bn(dh1536_p,sizeof(dh1536_p),NULL);
+    g=BN_bin2bn(dh1536_g,sizeof(dh1536_g),NULL);
+    if ((p == NULL) || (g == NULL))
@@ -984,0 +992 @@ get_dh1536()
+    DH_set0_pqg(dh, p, NULL, g);
@@ -991,0 +1000 @@ get_dh2048()
+    BIGNUM *p, *g;
@@ -995,3 +1004,3 @@ get_dh2048()
-    dh->p=BN_bin2bn(dh2048_p,sizeof(dh2048_p),NULL);
-    dh->g=BN_bin2bn(dh2048_g,sizeof(dh2048_g),NULL);
-    if ((dh->p == NULL) || (dh->g == NULL))
+    p=BN_bin2bn(dh2048_p,sizeof(dh2048_p),NULL);
+    g=BN_bin2bn(dh2048_g,sizeof(dh2048_g),NULL);
+    if ((p == NULL) || (g == NULL))
@@ -998,0 +1008 @@ get_dh2048()
+    DH_set0_pqg(dh, p, NULL, g);
@@ -1057,2 +1067,6 @@ ssl_display_comp(SSL * ssl)
-    if (ssl->expand == NULL || ssl->expand->meth == NULL)
-        printf("Compression: None\r\n");
+#ifndef OPENSSL_NO_COMP
+    const COMP_METHOD *x = SSL_get_current_expansion(ssl);
+    if (!x)
+#endif /* ifndef OPENSSL_NO_COMP */
+	printf("Compression: None\r\n");
+#ifndef OPENSSL_NO_COMP
@@ -1060 +1074 @@ ssl_display_comp(SSL * ssl)
-        printf("Compression: %s\r\n",ssl->expand->meth->name);
+        printf("Compression: %s\r\n", SSL_COMP_get_name(x));
@@ -1061,0 +1076 @@ ssl_display_comp(SSL * ssl)
+#endif /* ifndef OPENSSL_NO_COMP */
@@ -1460 +1475 @@ the build.\r\n\r\n");
-    if (cm != NULL && cm->type != NID_undef) {
+    if (cm != NULL && COMP_get_type(cm) != NID_undef) {
@@ -1463,0 +1479 @@ the build.\r\n\r\n");
+#if 0 /* COMP_rle has apparently been removed in OpenSSL 1.1 */
@@ -1466,0 +1483 @@ the build.\r\n\r\n");
+#endif
@@ -1486,6 +1503,3 @@ the build.\r\n\r\n");
-        rc1 = RAND_egd(ssl_rnd_file);
-        debug(F111,"ssl_once_init","RAND_egd()",rc1);
-        if ( rc1 <= 0 ) {
-            rc2 = RAND_load_file(ssl_rnd_file, -1);
-            debug(F111,"ssl_once_init","RAND_load_file()",rc1);
-        }
+        rc1 = -1;
+        rc2 = RAND_load_file(ssl_rnd_file, -1);
+        debug(F111,"ssl_once_init","RAND_load_file()",rc1);
@@ -1581,0 +1596 @@ ssl_tn_init(mode) int mode;
+#ifndef OPENSSL_NO_SSL3_METHOD
@@ -1582,0 +1598 @@ ssl_tn_init(mode) int mode;
+#endif /* ifndef OPENSSL_NO_SSL3_METHOD */
@@ -1584,0 +1601 @@ ssl_tn_init(mode) int mode;
+#ifndef OPENSSL_NO_SSL3_METHOD
@@ -1585,0 +1603 @@ ssl_tn_init(mode) int mode;
+#endif /* ifndef OPENSSL_NO_SSL3_METHOD */
@@ -1590 +1608 @@ ssl_tn_init(mode) int mode;
-            tls_ctx=(SSL_CTX *)SSL_CTX_new(TLSv1_client_method());
+            tls_ctx=(SSL_CTX *)SSL_CTX_new(TLS_client_method());
@@ -1592 +1610 @@ ssl_tn_init(mode) int mode;
-            tls_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_client_method());
+            tls_ctx=(SSL_CTX *)SSL_CTX_new(TLS_client_method());
@@ -1595,2 +1613,2 @@ ssl_tn_init(mode) int mode;
-                debug(F110,"ssl_tn_init","SSLv23_client_method failed",0);
-                tls_ctx=(SSL_CTX *)SSL_CTX_new(SSLv3_client_method());
+                debug(F110,"ssl_tn_init","TLS_client_method failed",0);
+                tls_ctx=(SSL_CTX *)SSL_CTX_new(TLSv1_client_method());
@@ -1614 +1632 @@ ssl_tn_init(mode) int mode;
-                ssl_ctx=(SSL_CTX *)SSL_CTX_new(SSLv3_server_method());
+                ssl_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_server_method());
@@ -1617 +1635 @@ ssl_tn_init(mode) int mode;
-                debug(F110,"ssl_tn_init","SSLv3_server_method failed",0);
+                debug(F110,"ssl_tn_init","SSLv23_server_method failed",0);
@@ -2164 +2182 @@ ssl_http_init(hostname) char * hostname;
-            tls_http_ctx=(SSL_CTX *)SSL_CTX_new(SSLv3_client_method());
+            tls_http_ctx=(SSL_CTX *)SSL_CTX_new(SSLv23_client_method());
@@ -2578 +2596 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-    X509_OBJECT obj;
+    X509_OBJECT *obj;
@@ -2644 +2662,5 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-    memset((char *)&obj, 0, sizeof(obj));
+    obj = X509_OBJECT_new();
+    if (!obj) {
+        X509_STORE_CTX_free(store_ctx);
+        return ok;
+    }
@@ -2646 +2668 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-    rc = X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, subject, &obj);
+    rc = X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, subject, obj);
@@ -2648 +2670 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-    crl = obj.data.crl;
+    crl = X509_OBJECT_get0_X509_CRL(obj);
@@ -2656 +2678 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-            X509_OBJECT_free_contents(&obj);
+            X509_OBJECT_free(obj);
@@ -2669 +2691 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-            X509_OBJECT_free_contents(&obj);
+            X509_OBJECT_free(obj);
@@ -2678 +2700 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-            X509_OBJECT_free_contents(&obj);
+            X509_OBJECT_free(obj);
@@ -2682 +2703,0 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-        X509_OBJECT_free_contents(&obj);
@@ -2689 +2710,6 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-    memset((char *)&obj, 0, sizeof(obj));
+    X509_OBJECT_free(obj);
+    obj = X509_OBJECT_new();
+    if (!obj) {
+        X509_STORE_CTX_free(store_ctx);
+        return ok;
+    }
@@ -2691 +2717 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-    rc = X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, issuer, &obj);
+    rc = X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, issuer, obj);
@@ -2693 +2719 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-    crl = obj.data.crl;
+    crl = X509_OBJECT_get0_X509_CRL(obj);
@@ -2701 +2727 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-            if (ASN1_INTEGER_cmp(revoked->serialNumber,
+            if (ASN1_INTEGER_cmp(X509_REVOKED_get0_serialNumber(revoked),
@@ -2704 +2730 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-                serial = ASN1_INTEGER_get(revoked->serialNumber);
+                serial = ASN1_INTEGER_get(X509_REVOKED_get0_serialNumber(revoked));
@@ -2709 +2735 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-                X509_OBJECT_free_contents(&obj);
+                X509_OBJECT_free(obj);
@@ -2713 +2738,0 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
-        X509_OBJECT_free_contents(&obj);
@@ -2714,0 +2740 @@ ssl_verify_crl(int ok, X509_STORE_CTX *ctx)
+    X509_OBJECT_free(obj);
@@ -4332,0 +4359 @@ X509_userok(X509 * peer_cert, const char * userid)
+    const ASN1_BIT_STRING *peer_sig, *file_sig;
@@ -4335,0 +4363 @@ X509_userok(X509 * peer_cert, const char * userid)
+    X509_get0_signature(&peer_sig, NULL, peer_cert);
@@ -4346 +4374,2 @@ X509_userok(X509 * peer_cert, const char * userid)
-        if (!ASN1_STRING_cmp(peer_cert->signature, file_cert->signature))
+        X509_get0_signature(&file_sig, NULL, file_cert);
+        if (!ASN1_STRING_cmp(peer_sig, file_sig))
diff --git a/ckcftp.c b/ckcftp.c
index 66c7940..1b57358 100644
--- a/ckcftp.c
+++ b/ckcftp.c
@@ -10199 +10199 @@ ssl_auth() {
-        ssl_ftp_ctx=SSL_CTX_new(SSLv3_client_method());
+        ssl_ftp_ctx=SSL_CTX_new(TLS_client_method());
@@ -10207 +10207 @@ ssl_auth() {
-                                  SSLv3_client_method());
+                                  TLS_client_method());
diff --git a/ckcpro.c b/ckcpro.c
index 3c51b6b..3da018f 100644
--- a/ckcpro.c
+++ b/ckcpro.c
@@ -171,0 +172 @@ _PROTOTYP( int cmdsrc, (void) );
+  extern int bctf;
@@ -506,0 +508,2 @@ case 11:
+
+    if (!bctf) {		     /* Block check 3 forced on all packets */
@@ -512,0 +516 @@ case 11:
+    }
@@ -513,0 +518 @@ case 11:
+    if (!bctf) {		     /* Block check 3 forced on all packets */
@@ -515,3 +520,4 @@ case 11:
-    if (epktflg) {			/* Restore the block check */
-	epktflg = 0;
-	bctl = b1; bctu = b2;
+	if (epktflg) {			/* Restore the block check */
+	    epktflg = 0;
+	    bctl = b1; bctu = b2;
+	}
@@ -1132 +1138 @@ case 37:
-	debug(F100,"C-Kermit BYE - Loggin out...","",0);
+	debug(F100,"C-Kermit BYE - Logging out...","",0);
@@ -1776,2 +1782,8 @@ case 62:
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
@@ -2929,2 +2941,7 @@ rcv_s_pkt() {
-	bctu = bctr;			/* Switch to agreed-upon block check */
-	bctl = (bctu == 4) ? 2 : bctu;	/* Set block-check length */
+	if (bctf) {
+	    bctu = 3;
+	    bctl = 3;
+	} else {
+	    bctu = bctr;	       /* switch to agreed-upon block check */
+	    bctl = (bctu == 4) ? 2 : bctu; /* Set block-check length */
+	}
diff --git a/ckctel.c b/ckctel.c
index e9f1295..ce1a1cc 100644
--- a/ckctel.c
+++ b/ckctel.c
@@ -4318,0 +4319,3 @@ tn_no_encrypt()
+#ifdef MACOSX
+    void ck_tn_enc_stop();
+#endif
diff --git a/ckuath.c b/ckuath.c
index ea9bc7d..0f53a33 100644
--- a/ckuath.c
+++ b/ckuath.c
@@ -4526 +4526 @@ k5_get_ccache(k5_context, p_ccache, cc_name)
-            com_err("k5_get_ccache",r,"while getting default ccache");
+            /* com_err("k5_get_ccache",r,"while getting default ccache"); */
@@ -10930 +10930 @@ ck_krb5_get_cc_name()
-            com_err("ck_krb5_get_cc_name",code,"while getting default ccache");
+            /* com_err("ck_krb5_get_cc_name",code,"while getting default ccache"); */
diff --git a/ckucns.c b/ckucns.c
index 337197c..8c14b38 100644
--- a/ckucns.c
+++ b/ckucns.c
@@ -197,0 +198 @@ extern int kstartactive;
+#include "ckuath.h"
diff --git a/ckufio.c b/ckufio.c
index b5bfaae..25194e5 100644
--- a/ckufio.c
+++ b/ckufio.c
@@ -43,0 +44 @@ char *ckzv = "UNIX File support, 9.0.216, 20 Aug 2011";
+#include "ckuath.h"
diff --git a/ckupty.c b/ckupty.c
index 9906555..b6d2264 100644
--- a/ckupty.c
+++ b/ckupty.c
@@ -69,0 +70,4 @@ char * ptyver = "PTY support 8.0.016, 22 Aug 2007";
+#ifdef MACOSX
+#include <util.h>
+#endif
+
diff --git a/ckutio.c b/ckutio.c
index 05564de..f336f67 100644
--- a/ckutio.c
+++ b/ckutio.c
@@ -374,0 +375,4 @@ char unm_ver[CK_SYSNMLN+1] = { '\0', '\0' };
+#ifdef MACOSX
+#include <util.h>
+#endif /* MACOSX */
+
@@ -14663,0 +14668,3 @@ ttptycmd(s) char *s; {
+#ifdef MACOSX
+    int openpty(int *aprimary, int *areplica, char *name, struct termios *termp, struct winsize *winp);
+#endif
diff --git a/ckuus3.c b/ckuus3.c
index 5887b34..e7e10d0 100644
--- a/ckuus3.c
+++ b/ckuus3.c
@@ -10308,0 +10309 @@ case XYCARR:                            /* CARRIER-WATCH */
+		  void ck_tn_enc_start();
@@ -10319,0 +10321 @@ case XYCARR:                            /* CARRIER-WATCH */
+		  void ck_tn_enc_stop();
diff --git a/ckuusr.c b/ckuusr.c
index 3b77fe6..4a756b2 100644
--- a/ckuusr.c
+++ b/ckuusr.c
@@ -95,0 +96 @@ char *userv = "User Interface 9.0.299, 9 Jun 2011";
+#include "ckuath.h"
diff --git a/ckuusx.c b/ckuusx.c
index d332bed..df5e545 100644
--- a/ckuusx.c
+++ b/ckuusx.c
@@ -65,0 +66,3 @@
+#ifdef CK_NCURSES
+#include <term.h>
+#endif /* ifdef CK_NCURSES */
@@ -66,0 +70 @@
+
diff --git a/makefile b/makefile
index 9efe262..b5ef2b7 100644
--- a/makefile
+++ b/makefile
@@ -2137 +2137 @@ macosx+krb5+openssl macosx10.5+krb5+openssl macosx10.6+krb5+openssl:
-	-DCKCPU=\"\\\"$${MACCPU}\\\"\" \
+	-Wno-implicit-function-declaration -DCKCPU=\"\\\"$${MACCPU}\\\"\" \
@@ -2139 +2139 @@ macosx+krb5+openssl macosx10.5+krb5+openssl macosx10.6+krb5+openssl:
-	"LIBS= $$HAVE_KRB5CONFIG -lssl -lcrypto -lpam -lncurses $(LIBS)"
+	"LIBS= $$HAVE_KRB5CONFIG -lssl -lcrypto -lpam -lncurses -lresolv $(LIBS)"
@@ -6305 +6305 @@ linux+krb5+ssl linux+krb5+openssl:
-	K5CRYPTO=''; \
+	K5CRYPTO='-lk5crypto'; \
@@ -6313 +6313 @@ linux+krb5+ssl linux+krb5+openssl:
-	COM_ERR=''; \
+	COM_ERR='-lcom_err'; \
@@ -6317 +6317 @@ linux+krb5+ssl linux+krb5+openssl:
-	GSSAPILIB='-lgssapi'; \
+	GSSAPILIB='-lgssapi_krb5'; \
@@ -6332 +6332 @@ linux+krb5+ssl linux+krb5+openssl:
-	-lcrypto $$GSSAPILIB -lkrb5 $$K5CRYPTO $$COM_ERR $(LIBS)" ; \
+	-lcrypto $$GSSAPILIB -lkrb5 $$K5CRYPTO $$COM_ERR -lncurses $(LIBS)" ; \
