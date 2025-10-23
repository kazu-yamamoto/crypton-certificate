{-# LANGUAGE CPP #-}

module Data.X509.File (
    readSignedObject,
    readKeyFile,
    PEMError (..),
) where

import Control.Applicative
import Control.Exception (Exception (..), throw)
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types
import qualified Data.ByteString.Lazy as L
import Data.Maybe
import Data.PEM (PEM, pemContent, pemName, pemParseLBS)
import qualified Data.X509 as X509
import Data.X509.Memory (pemToKey)
#if !defined(mingw32_HOST_OS)
import System.Posix.IO
#endif

newtype PEMError = PEMError {displayPEMError :: String}
    deriving (Show)

instance Exception PEMError where
    displayException = displayPEMError

readPEMs :: FilePath -> IO [PEM]
readPEMs filepath = do
#if defined(mingw32_HOST_OS)
    content <- L.readFile filepath
#else
    fd <- openFd filepath ReadOnly defaultFileFlags{cloexec = True}
    h <- fdToHandle fd
    content <- L.hGetContents h
#endif
    either (throw . PEMError) pure $ pemParseLBS content

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
readKeyFile path = catMaybes . foldl pemToKey [] <$> readPEMs path
