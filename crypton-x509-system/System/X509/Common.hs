module System.X509.Common (
    maybeSSLCertEnvOr,
    nativeCertificates,
)
where

import Control.Exception (bracket)
import Control.Monad (when)
import Data.Bits (shiftL, (.|.))
import qualified Data.ByteString as B
import Data.Either (rights)
import Data.Maybe (catMaybes, maybeToList)
import Data.Word (Word8)
import Data.X509
import Data.X509.CertificateStore
import Foreign.C.Types (CInt (..), CSize (..))
import Foreign.Marshal.Alloc (alloca, free)
import Foreign.Ptr (Ptr, castPtr)
import Foreign.Storable (peek)
import System.Environment (lookupEnv)
import System.FilePath (searchPathSeparator)

-- | Like OpenSSL, the certificates in @SSL_CERT_FILE@ and in the
-- directories listed in @SSL_CERT_DIR@ replace the default store if
-- either variable is set to a non-empty value.
maybeSSLCertEnvOr :: IO CertificateStore -> IO CertificateStore
maybeSSLCertEnvOr defaultStore = do
    file <- nonEmpty <$> lookupEnv "SSL_CERT_FILE"
    dirs <- maybe [] splitDirs <$> lookupEnv "SSL_CERT_DIR"
    case maybeToList file ++ dirs of
        [] -> defaultStore
        paths -> mconcat . catMaybes <$> mapM readCertificateStore paths
  where
    nonEmpty (Just s) | not (null s) = Just s
    nonEmpty _ = Nothing
    splitDirs s = case break (== searchPathSeparator) s of
        (d, []) -> [d | not (null d)]
        (d, _ : rest) -> [d | not (null d)] ++ splitDirs rest

-- | Certificates returned by a C function as a malloc'ed buffer of 4-byte
-- big-endian lengths each followed by DER.  The first argument names the
-- caller in errors.
nativeCertificates
    :: String
    -> (Ptr (Ptr Word8) -> Ptr CSize -> IO CInt)
    -> IO [SignedCertificate]
nativeCertificates name getCerts =
    alloca $ \pbuf -> alloca $ \plen -> do
        rc <- getCerts pbuf plen
        when (rc /= 0) $
            ioError $
                userError $
                    name ++ ": cannot get the trusted certificates: " ++ show rc
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
