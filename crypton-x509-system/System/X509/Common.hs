module System.X509.Common (
    maybeSSLCertEnvOr,
)
where

import Data.Maybe (catMaybes, maybeToList)
import Data.X509.CertificateStore
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
