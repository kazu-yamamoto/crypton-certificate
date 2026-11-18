{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Data.X509.CRL
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Read and Write X509 Certificate Revocation List (CRL).
--
-- follows RFC5280 / RFC6818.
module Data.X509.CRL (
    CRL (..),
    RevokedCertificate (..),
) where

import Data.ASN1.Types
import Data.Hourglass (DateTime)

import Data.X509.AlgorithmIdentifier
import Data.X509.DistinguishedName
import Data.X509.ExtensionRaw
import Data.X509.Internal

-- | Describe a Certificate revocation list
data CRL = CRL
    { crlVersion :: Integer
    , crlSignatureAlg :: SignatureALG
    , crlIssuer :: DistinguishedName
    , crlThisUpdate :: DateTime
    , crlNextUpdate :: Maybe DateTime
    , crlRevokedCertificates :: [RevokedCertificate]
    , crlExtensions :: Extensions
    }
    deriving (Show, Eq)

-- | Describe a revoked certificate identifiable by serial number.
data RevokedCertificate = RevokedCertificate
    { revokedSerialNumber :: Integer
    , revokedDate :: DateTime
    , revokedExtensions :: Extensions
    }
    deriving (Show, Eq)

instance ASN1Object CRL where
    toASN1 crl = encodeCRL crl
    fromASN1 = runParseASN1State parseCRL

instance ASN1Object RevokedCertificate where
    fromASN1 =
        runParseASN1State $
            onNextContainer Sequence $
                RevokedCertificate
                    <$> parseSerialNumber
                    <*> (getNext >>= toTime)
                    <*> getObject
      where
        toTime (ASN1Time _ t z) = pure (asn1TimeToUTC t z)
        toTime _ = throwParseError "bad revocation date"
    toASN1 (RevokedCertificate serial time crlEntryExtensions) = \xs ->
        [Start Sequence]
            ++ [IntVal serial]
            ++ [encodeASN1Time time]
            ++ toASN1 crlEntryExtensions []
            ++ [End Sequence]
            ++ xs

parseSerialNumber :: ParseASN1 Integer
parseSerialNumber = do
    n <- getNext
    case n of
        IntVal v -> return v
        _ -> throwParseError ("missing serial" ++ show n)

parseCRL :: ParseASN1 CRL
parseCRL = do
    CRL
        -- the version is absent in v1 CRLs
        <$> (maybe 0 id <$> getNextMaybe getVersion)
        <*> getObject
        <*> getObject
        <*> (getNext >>= getThisUpdate)
        <*> getNextUpdate
        <*> parseRevokedCertificates
        <*> parseCRLExtensions
  where
    getVersion (IntVal v) = Just v
    getVersion _ = Nothing

    getThisUpdate (ASN1Time _ t1 z) = return (asn1TimeToUTC t1 z)
    getThisUpdate _ = throwParseError "bad this update format, expecting time"

    getNextUpdate = getNextMaybe timeOrNothing

    timeOrNothing (ASN1Time _ tnext z) = Just (asn1TimeToUTC tnext z)
    timeOrNothing _ = Nothing

parseRevokedCertificates :: ParseASN1 [RevokedCertificate]
parseRevokedCertificates =
    fmap (maybe [] id) $ onNextContainerMaybe Sequence $ getMany getObject

parseCRLExtensions :: ParseASN1 Extensions
parseCRLExtensions =
    fmap adapt $ onNextContainerMaybe (Container Context 0) $ getObject
  where
    adapt (Just e) = e
    adapt Nothing = Extensions Nothing

encodeCRL :: CRL -> ASN1S
encodeCRL crl xs =
    [IntVal (crlVersion crl) | crlVersion crl /= 0]
        ++ toASN1 (crlSignatureAlg crl) []
        ++ toASN1 (crlIssuer crl) []
        ++ [encodeASN1Time (crlThisUpdate crl)]
        ++ maybe [] (\t -> [encodeASN1Time t]) (crlNextUpdate crl)
        ++ maybeRevoked (crlRevokedCertificates crl)
        ++ maybeCrlExts (crlExtensions crl)
        ++ xs
  where
    maybeRevoked [] = []
    maybeRevoked xs' = asn1Container Sequence $ concatMap (\e -> toASN1 e []) xs'
    maybeCrlExts (Extensions Nothing) = []
    maybeCrlExts exts = asn1Container (Container Context 0) $ toASN1 exts []
