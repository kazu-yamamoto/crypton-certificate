{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Data.X509.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
module Data.X509.Internal (
    module Data.ASN1.Parse,
    asn1Container,
    OID,

    -- * error handling
    ErrT,
    runErrT,
    safeDecode,
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
import Control.Monad.Trans.Except
import Data.ASN1.Parse
import Data.ASN1.Types
import qualified Data.List as L
import System.IO.Unsafe (unsafeDupablePerformIO)

runErrT :: ExceptT e m a -> m (Either e a)
runErrT = runExceptT
type ErrT = ExceptT

-- | create a container around the stream of ASN1
asn1Container :: ASN1ConstructionType -> [ASN1] -> [ASN1]
asn1Container ty l = [Start ty] ++ l ++ [End ty]

-- | Force a decoded ASN.1 stream so that errors thrown lazily from inside
-- the list by the decoder are turned into 'Left'.
safeDecode :: Show e => Either e [a] -> Either String [a]
safeDecode r = case tryPure forceE r of
    Left err -> Left err
    Right (Left e) -> Left (show e)
    Right (Right xs) -> Right xs
  where
    forceE (Left e) = length (show e) `seq` ()
    forceE (Right xs) = L.foldl' (flip seq) () xs

-- | Like 'asn1CharacterToString' but 'Nothing' on invalid encoding.
safeCharacterToString :: ASN1CharacterString -> Maybe String
safeCharacterToString cs =
    asn1CharacterToString cs >>= either (const Nothing) Just . tryPure force
  where
    force = L.foldl' (flip seq) ()

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
