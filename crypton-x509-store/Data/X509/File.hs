module Data.X509.File (
    readSignedObject,
    readKeyFile,
    PEMError (..),
) where

import qualified Control.Exception as E
import Data.ASN1.Types
import Data.Maybe
import Data.PEM (PEM, pemContent, pemParseBS)
import qualified Data.X509 as X509
import Data.X509.Memory (pemToKey)
import Data.X509.ReadFile (readFileCloexec)

newtype PEMError = PEMError {displayPEMError :: String}
    deriving (Show)

instance E.Exception PEMError where
    displayException = displayPEMError

readPEMs :: FilePath -> IO [PEM]
readPEMs filepath = do
    content <- readFileCloexec filepath
    either (E.throwIO . PEMError) pure $ pemParseBS content

-- | return all the signed objects in a file.
--
-- (only one type at a time).
readSignedObject
    :: (ASN1Object a, Eq a, Show a)
    => FilePath
    -> IO [X509.SignedExact a]
readSignedObject filepath = decodePEMs <$> readPEMs filepath
  where
    decodePEMs pems =
        [obj | pem <- pems, Right obj <- [X509.decodeSignedObject $ pemContent pem]]

-- | return all the private keys that were successfully read from a file.
readKeyFile :: FilePath -> IO [X509.PrivKey]
readKeyFile path = catMaybes . concatMap (pemToKey []) <$> readPEMs path
