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

    -- * time
    asn1TimeToUTC,
    encodeASN1Time,
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
import Data.Hourglass
import qualified Data.List as L
import System.IO.Unsafe (unsafeDupablePerformIO)

runErrT :: ExceptT e m a -> m (Either e a)
runErrT = runExceptT
type ErrT = ExceptT

-- | A decoded time converted to UTC with its zone offset.
asn1TimeToUTC :: DateTime -> Maybe TimezoneOffset -> DateTime
asn1TimeToUTC t (Just (TimezoneOffset m))
    | m /= 0 = timeAdd t (Seconds (fromIntegral (negate m) * 60))
asn1TimeToUTC t _ = t

-- | RFC 5280 4.1.2.5: UTCTime through 2049 from 1950, GeneralizedTime
-- otherwise.
encodeASN1Time :: DateTime -> ASN1
encodeASN1Time t = ASN1Time ty t (Just (TimezoneOffset 0))
  where
    y = dateYear (dtDate t)
    ty
        | y >= 1950 && y < 2050 = TimeUTC
        | otherwise = TimeGeneralized

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
