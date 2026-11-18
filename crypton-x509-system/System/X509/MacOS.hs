module System.X509.MacOS (
    getSystemCertificateStore,
) where

import Control.Exception (bracket)
import Control.Monad (when)
import Data.Bits (shiftL, (.|.))
import qualified Data.ByteString as B
import Data.Either
import Data.Word (Word8)
import Foreign.C.Types
import Foreign.Marshal.Alloc (alloca, free)
import Foreign.Ptr
import Foreign.Storable

import Data.X509
import Data.X509.CertificateStore
import System.X509.Common (maybeSSLCertEnvOr)

foreign import ccall safe "hs_x509_trusted_certificates"
    c_trustedCertificates :: Ptr (Ptr Word8) -> Ptr CSize -> IO CInt

-- | Certificates trusted as TLS anchors according to the trust settings
-- of the user, admin and system domains.
trustedCertificates :: IO [SignedCertificate]
trustedCertificates =
    alloca $ \pbuf -> alloca $ \plen -> do
        rc <- c_trustedCertificates pbuf plen
        when (rc /= 0) $
            ioError $
                userError $
                    "System.X509.MacOS: cannot get trust settings: " ++ show rc
        bracket (peek pbuf) free $ \buf -> do
            len <- peek plen
            bs <- B.packCStringLen (castPtr buf, fromIntegral len)
            return $ rights $ map decodeSignedCertificate $ split bs
  where
    split bs
        | B.length bs < 4 = []
        | otherwise =
            let (hdr, rest) = B.splitAt 4 bs
                n = foldl (\a w -> a `shiftL` 8 .|. fromIntegral w) 0 (B.unpack hdr)
                (der, rest') = B.splitAt n rest
             in der : split rest'

getSystemCertificateStore :: IO CertificateStore
getSystemCertificateStore =
    maybeSSLCertEnvOr (makeCertificateStore <$> trustedCertificates)
