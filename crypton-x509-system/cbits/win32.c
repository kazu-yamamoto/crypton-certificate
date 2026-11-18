#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <wincrypt.h>

/* Whether the enhanced key usage property allows server authentication.
   Without the property, the certificate is good for all uses; an empty
   property means it is disabled. */
static int usable_for_tls(PCCERT_CONTEXT ctx) {
    const DWORD flag = CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG;
    DWORD size = 0;
    if (!CertGetEnhancedKeyUsage(ctx, flag, NULL, &size))
        return GetLastError() == (DWORD)CRYPT_E_NOT_FOUND;
    PCERT_ENHKEY_USAGE usage = malloc(size);
    if (usage == NULL)
        return 0;
    int ok = 0;
    SetLastError(0);
    if (!CertGetEnhancedKeyUsage(ctx, flag, usage, &size)) {
        ok = GetLastError() == (DWORD)CRYPT_E_NOT_FOUND;
    } else if (usage->cUsageIdentifier == 0) {
        ok = GetLastError() == (DWORD)CRYPT_E_NOT_FOUND;
    } else {
        for (DWORD i = 0; i < usage->cUsageIdentifier; i++)
            if (strcmp(usage->rgpszUsageIdentifier[i], szOID_PKIX_KP_SERVER_AUTH) == 0)
                ok = 1;
    }
    free(usage);
    return ok;
}

static int disallowed(HCERTSTORE dis, PCCERT_CONTEXT ctx) {
    if (dis == NULL)
        return 0;
    PCCERT_CONTEXT found = CertFindCertificateInStore(
        dis, ctx->dwCertEncodingType, 0, CERT_FIND_EXISTING, ctx, NULL);
    if (found == NULL)
        return 0;
    CertFreeCertificateContext(found);
    return 1;
}

/* Root certificates usable for TLS server authentication and not in the
   Disallowed store, as a malloc'ed buffer of 4-byte big-endian lengths
   each followed by DER. */
int hs_x509_win32_trusted_certificates(uint8_t **out, size_t *outlen) {
    *out = NULL;
    *outlen = 0;
    HCERTSTORE root = CertOpenSystemStoreW(0, L"ROOT");
    if (root == NULL)
        return -1;
    HCERTSTORE dis = CertOpenSystemStoreW(0, L"Disallowed");

    int ret = 0;
    uint8_t *buf = NULL;
    size_t len = 0, cap = 0;
    PCCERT_CONTEXT ctx = NULL;
    while ((ctx = CertEnumCertificatesInStore(root, ctx)) != NULL) {
        if ((ctx->dwCertEncodingType & X509_ASN_ENCODING) == 0 ||
            !usable_for_tls(ctx) || disallowed(dis, ctx))
            continue;
        size_t n = ctx->cbCertEncoded;
        if (len + 4 + n > cap) {
            size_t newcap = (cap + 4 + n) * 2;
            uint8_t *p = realloc(buf, newcap);
            if (p == NULL) {
                CertFreeCertificateContext(ctx);
                ret = -1;
                break;
            }
            buf = p;
            cap = newcap;
        }
        buf[len] = (uint8_t)(n >> 24);
        buf[len + 1] = (uint8_t)(n >> 16);
        buf[len + 2] = (uint8_t)(n >> 8);
        buf[len + 3] = (uint8_t)n;
        memcpy(buf + len + 4, ctx->pbCertEncoded, n);
        len += 4 + n;
    }
    if (dis != NULL)
        CertCloseStore(dis, 0);
    CertCloseStore(root, 0);
    if (ret != 0) {
        free(buf);
        return ret;
    }
    *out = buf;
    *outlen = len;
    return 0;
}
