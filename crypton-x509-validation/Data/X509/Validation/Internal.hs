{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Data.X509.Validation.Internal
-- License     : BSD-style
-- Stability   : experimental
-- Portability : unknown
--
-- Guards against exceptions thrown from pure code on malformed input.
module Data.X509.Validation.Internal (
    tryPure,
    safeCharacterToString,
) where

import Control.Exception (
    SomeAsyncException,
    SomeException,
    evaluate,
    fromException,
    throwIO,
    try,
 )
import Data.ASN1.Types (ASN1CharacterString, asn1CharacterToString)
import qualified Data.List as L
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | Run a forcing function and turn synchronous exceptions into 'Left'.
tryPure :: (a -> ()) -> a -> Either String a
tryPure force x = unsafeDupablePerformIO $ do
    res <- try $ evaluate $ force x
    case res of
        Right () -> return $ Right x
        Left (e :: SomeException)
            | Just (_ :: SomeAsyncException) <- fromException e -> throwIO e
            | otherwise -> return $ Left (show e)
{-# NOINLINE tryPure #-}

-- | Like 'asn1CharacterToString' but 'Nothing' on invalid encoding.
safeCharacterToString :: ASN1CharacterString -> Maybe String
safeCharacterToString cs =
    asn1CharacterToString cs >>= either (const Nothing) Just . tryPure force
  where
    force = L.foldl' (flip seq) ()
