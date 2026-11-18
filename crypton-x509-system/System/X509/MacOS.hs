module System.X509.MacOS (
    getSystemCertificateStore,
) where

import Data.Word (Word8)
import Foreign.C.Types
import Foreign.Ptr

import Data.X509.CertificateStore
import System.X509.Common (maybeSSLCertEnvOr, nativeCertificates)

foreign import ccall safe "hs_x509_trusted_certificates"
    c_trustedCertificates :: Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

-- | Certificates trusted as TLS anchors according to the trust settings
-- of the user, admin and system domains.
getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore =
    maybeSSLCertEnvOr $
        makeCertificateStore
            <$> nativeCertificates "System.X509.MacOS" c_trustedCertificates
