module System.X509.Win32 (
    getSystemCertificateStore,
) where

import Data.Word (Word8)
import Foreign.C.Types
import Foreign.Ptr

import Data.X509.CertificateStore
import System.X509.Common (maybeSSLCertEnvOr, nativeCertificates)

foreign import ccall safe "hs_x509_win32_trusted_certificates"
    c_trustedCertificates :: Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

-- | Certificates in the ROOT store that are enabled for server
-- authentication and not in the Disallowed store.
getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore =
    maybeSSLCertEnvOr $
        makeCertificateStore
            <$> nativeCertificates "System.X509.Win32" c_trustedCertificates
