module System.X509.Common (
    maybeSSLCertEnvOr,
)
where

import Data.Foldable (asum)
import Data.Maybe (fromMaybe)
import Data.X509.CertificateStore
import System.Environment (lookupEnv)

getOpenSslEnvs :: IO (Maybe String)
getOpenSslEnvs =
    asum
        <$> traverse
            lookupEnv
            [ "SSL_CERT_FILE"
            , "SSL_CERT_DIR"
            ]

maybeSSLCertEnvOr :: IO CertificateStore -> IO CertificateStore
maybeSSLCertEnvOr defaultStore = do
    overrideCertPaths <- getOpenSslEnvs
    case overrideCertPaths of
        Nothing -> defaultStore
        Just certPath -> fromMaybe mempty <$> (readCertificateStore certPath)
