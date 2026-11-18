#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

enum { UNDECIDED, TRUSTED, DISTRUSTED };

/* Whether a usage constraint applies to TLS in general. */
static int applies_to_tls(CFDictionaryRef c) {
    if (CFDictionaryContainsKey(c, kSecTrustSettingsApplication) ||
        CFDictionaryContainsKey(c, kSecTrustSettingsPolicyString))
        return 0;
    CFTypeRef policy = CFDictionaryGetValue(c, kSecTrustSettingsPolicy);
    if (policy == NULL)
        return 1;
    if (CFGetTypeID(policy) != SecPolicyGetTypeID())
        return 0;
    CFDictionaryRef props = SecPolicyCopyProperties((SecPolicyRef)policy);
    if (props == NULL)
        return 0;
    CFTypeRef oid = CFDictionaryGetValue(props, kSecPolicyOid);
    int ok = oid != NULL && CFEqual(oid, kSecPolicyAppleSSL);
    CFRelease(props);
    return ok;
}

/* The trust settings of a certificate in a domain.  An empty array
   means "always trust" and a missing result means TrustRoot. */
static int decide(SecCertificateRef cert, SecTrustSettingsDomain domain) {
    CFArrayRef settings = NULL;
    if (SecTrustSettingsCopyTrustSettings(cert, domain, &settings) != errSecSuccess ||
        settings == NULL)
        return UNDECIDED;
    CFIndex n = CFArrayGetCount(settings);
    int decision = n == 0 ? TRUSTED : UNDECIDED;
    for (CFIndex i = 0; i < n && decision == UNDECIDED; i++) {
        CFTypeRef c = CFArrayGetValueAtIndex(settings, i);
        if (CFGetTypeID(c) != CFDictionaryGetTypeID() || !applies_to_tls(c))
            continue;
        SInt32 result = kSecTrustSettingsResultTrustRoot;
        CFTypeRef r = CFDictionaryGetValue(c, kSecTrustSettingsResult);
        if (r != NULL && CFGetTypeID(r) == CFNumberGetTypeID())
            CFNumberGetValue(r, kCFNumberSInt32Type, &result);
        if (result == kSecTrustSettingsResultTrustRoot ||
            result == kSecTrustSettingsResultTrustAsRoot)
            decision = TRUSTED;
        else if (result == kSecTrustSettingsResultDeny)
            decision = DISTRUSTED;
        /* Unspecified: look at the next constraint */
    }
    CFRelease(settings);
    return decision;
}

static const SecTrustSettingsDomain domains[] = {
    kSecTrustSettingsDomainUser,
    kSecTrustSettingsDomainAdmin,
    kSecTrustSettingsDomainSystem,
};
#define NDOMAINS (sizeof(domains) / sizeof(domains[0]))

/* Certificates trusted as TLS anchors, as a malloc'ed buffer of
   4-byte big-endian lengths each followed by DER.  The user domain
   overrides the admin domain, which overrides the system domain. */
int hs_x509_trusted_certificates(uint8_t **out, size_t *outlen) {
    *out = NULL;
    *outlen = 0;
    CFMutableSetRef all = CFSetCreateMutable(NULL, 0, &kCFTypeSetCallBacks);
    if (all == NULL)
        return -1;
    for (size_t d = 0; d < NDOMAINS; d++) {
        CFArrayRef certs = NULL;
        OSStatus st = SecTrustSettingsCopyCertificates(domains[d], &certs);
        if (st == errSecNoTrustSettings)
            continue;
        if (st != errSecSuccess) {
            CFRelease(all);
            return (int)st;
        }
        for (CFIndex i = 0; i < CFArrayGetCount(certs); i++)
            CFSetAddValue(all, CFArrayGetValueAtIndex(certs, i));
        CFRelease(certs);
    }

    CFIndex n = CFSetGetCount(all);
    const void **certs = calloc(n > 0 ? n : 1, sizeof(void *));
    CFDataRef *ders = calloc(n > 0 ? n : 1, sizeof(CFDataRef));
    if (certs == NULL || ders == NULL) {
        free(certs);
        free(ders);
        CFRelease(all);
        return -1;
    }
    CFSetGetValues(all, certs);

    size_t total = 0;
    for (CFIndex i = 0; i < n; i++) {
        SecCertificateRef cert = (SecCertificateRef)certs[i];
        int decision = UNDECIDED;
        for (size_t d = 0; d < NDOMAINS && decision == UNDECIDED; d++)
            decision = decide(cert, domains[d]);
        if (decision != TRUSTED)
            continue;
        ders[i] = SecCertificateCopyData(cert);
        if (ders[i] != NULL)
            total += 4 + (size_t)CFDataGetLength(ders[i]);
    }

    int ret = 0;
    uint8_t *buf = malloc(total > 0 ? total : 1);
    if (buf == NULL) {
        ret = -1;
    } else {
        uint8_t *p = buf;
        for (CFIndex i = 0; i < n; i++) {
            if (ders[i] == NULL)
                continue;
            uint32_t len = (uint32_t)CFDataGetLength(ders[i]);
            p[0] = len >> 24;
            p[1] = len >> 16;
            p[2] = len >> 8;
            p[3] = len;
            memcpy(p + 4, CFDataGetBytePtr(ders[i]), len);
            p += 4 + len;
        }
        *out = buf;
        *outlen = total;
    }
    for (CFIndex i = 0; i < n; i++)
        if (ders[i] != NULL)
            CFRelease(ders[i]);
    free(ders);
    free(certs);
    CFRelease(all);
    return ret;
}

#else

int hs_x509_trusted_certificates(uint8_t **out, size_t *outlen) {
    *out = NULL;
    *outlen = 0;
    return -1;
}

#endif
