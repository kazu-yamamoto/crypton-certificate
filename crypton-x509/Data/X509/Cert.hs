{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Data.X509.Cert
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Certificate types and functions
module Data.X509.Cert (Certificate (..)) where

import Data.ASN1.Types
import Data.Hourglass
import Data.X509.AlgorithmIdentifier
import Data.X509.DistinguishedName
import Data.X509.ExtensionRaw
import Data.X509.Internal
import Data.X509.PublicKey

data CertKeyUsage
    = CertKeyUsageDigitalSignature
    | CertKeyUsageNonRepudiation
    | CertKeyUsageKeyEncipherment
    | CertKeyUsageDataEncipherment
    | CertKeyUsageKeyAgreement
    | CertKeyUsageKeyCertSign
    | CertKeyUsageCRLSign
    | CertKeyUsageEncipherOnly
    | CertKeyUsageDecipherOnly
    deriving (Show, Eq)

-- | X.509 Certificate type.
--
-- This type doesn't include the signature, it's describe in the RFC
-- as tbsCertificate.
data Certificate = Certificate
    { certVersion :: Int
    -- ^ Version
    , certSerial :: Integer
    -- ^ Serial number
    , certSignatureAlg :: SignatureALG
    -- ^ Signature algorithm
    , certIssuerDN :: DistinguishedName
    -- ^ Issuer DN
    , certValidity :: (DateTime, DateTime)
    -- ^ Validity period (UTC)
    , certSubjectDN :: DistinguishedName
    -- ^ Subject DN
    , certPubKey :: PubKey
    -- ^ Public key
    , certExtensions :: Extensions
    -- ^ Extensions
    }
    deriving (Show, Eq)

instance ASN1Object Certificate where
    toASN1 certificate = \xs -> encodeCertificateHeader certificate ++ xs
    fromASN1 s = runParseASN1State parseCertificate s

parseCertHeaderVersion :: ParseASN1 Int
parseCertHeaderVersion =
    maybe 0 id <$> onNextContainerMaybe (Container Context 0) (getNext >>= getVer)
  where
    getVer (IntVal v)
        | v >= 0 && v <= 2 = return $ fromIntegral v
        | otherwise = throwParseError ("unsupported version " ++ show v)
    getVer _ = throwParseError "unexpected type for version"

parseCertHeaderSerial :: ParseASN1 Integer
parseCertHeaderSerial = do
    n <- getNext
    case n of
        IntVal v -> return v
        _ -> throwParseError ("missing serial" ++ show n)

parseCertHeaderValidity :: ParseASN1 (DateTime, DateTime)
parseCertHeaderValidity = getNextContainer Sequence >>= toTimeBound
  where
    toTimeBound [ASN1Time _ t1 z1, ASN1Time _ t2 z2] =
        return (asn1TimeToUTC t1 z1, asn1TimeToUTC t2 z2)
    toTimeBound _ = throwParseError "bad validity format"

-- | parse header structure of a x509 certificate. the structure is the following:
--         Version
--         Serial Number
--         Algorithm ID
--         Issuer
--         Validity
--                 Not Before
--                 Not After
--         Subject
--         Subject Public Key Info
--                 Public Key Algorithm
--                 Subject Public Key
--         Issuer Unique Identifier (Optional)  (>= 2)
--         Subject Unique Identifier (Optional) (>= 2)
--         Extensions (Optional)   (>= v3)
parseExtensions :: ParseASN1 Extensions
parseExtensions = fmap adapt $ onNextContainerMaybe (Container Context 3) $ getObject
  where
    adapt (Just e) = e
    adapt Nothing = Extensions Nothing

-- | issuerUniqueID and subjectUniqueID are skipped.
parseUniqueIDs :: ParseASN1 ()
parseUniqueIDs = uid 1 >> uid 2 >> return ()
  where
    uid n = getNextMaybe (\a -> if isUID n a then Just () else Nothing)
    isUID n (Other Context m _) = n == m
    isUID _ _ = False

parseCertificate :: ParseASN1 Certificate
parseCertificate =
    Certificate
        <$> parseCertHeaderVersion
        <*> parseCertHeaderSerial
        <*> getObject
        <*> getObject
        <*> parseCertHeaderValidity
        <*> getObject
        <*> (getObject <* parseUniqueIDs)
        <*> parseExtensions

encodeCertificateHeader :: Certificate -> [ASN1]
encodeCertificateHeader cert =
    eVer
        ++ eSerial
        ++ eAlgId
        ++ eIssuer
        ++ eValidity
        ++ eSubject
        ++ epkinfo
        ++ eexts
  where
    eVer =
        asn1Container (Container Context 0) [IntVal (fromIntegral $ certVersion cert)]
    eSerial = [IntVal $ certSerial cert]
    eAlgId = toASN1 (certSignatureAlg cert) []
    eIssuer = toASN1 (certIssuerDN cert) []
    (t1, t2) = certValidity cert
    eValidity =
        asn1Container
            Sequence
            [encodeASN1Time t1, encodeASN1Time t2]
    eSubject = toASN1 (certSubjectDN cert) []
    epkinfo = toASN1 (certPubKey cert) []
    eexts = case certExtensions cert of
        Extensions Nothing -> []
        exts -> asn1Container (Container Context 3) $ toASN1 exts []
