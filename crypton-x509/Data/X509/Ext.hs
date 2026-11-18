{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Data.X509.Ext
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- extension processing module.
module Data.X509.Ext (
    Extension (..),

    -- * Common extension usually found in x509v3
    ExtBasicConstraints (..),
    ExtKeyUsage (..),
    ExtKeyUsageFlag (..),
    ExtExtendedKeyUsage (..),
    ExtKeyUsagePurpose (..),
    ExtSubjectKeyId (..),
    ExtSubjectAltName (..),
    ExtAuthorityKeyId (..),
    ExtCrlDistributionPoints (..),
    ExtNetscapeComment (..),
    ExtNameConstraints (..),
    GeneralSubtree (..),
    AltName (..),
    DistributionPoint (..),
    ReasonFlag (..),

    -- * Accessor turning extension into a specific one
    extensionGet,
    extensionGetE,
    extensionDecode,
    extensionEncode,
    recognizedOIDs,
) where

import Control.Monad
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import Data.ASN1.Encoding
import Data.ASN1.Parse
import Data.ASN1.Types
import Data.Bits (bit, shiftR, testBit, (.&.), (.|.))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.List (find)
import Data.Maybe (catMaybes)
import Data.Proxy
import Data.X509.DistinguishedName
import Data.X509.ExtensionRaw
import Data.X509.Internal (safeCharacterToString, safeDecode)

-- | key usage flag that is found in the key usage extension field.
data ExtKeyUsageFlag
    = KeyUsage_digitalSignature -- (0)
    | KeyUsage_nonRepudiation -- (1) recent X.509 ver have renamed this bit to contentCommitment
    | KeyUsage_keyEncipherment -- (2)
    | KeyUsage_dataEncipherment -- (3)
    | KeyUsage_keyAgreement -- (4)
    | KeyUsage_keyCertSign -- (5)
    | KeyUsage_cRLSign -- (6)
    | KeyUsage_encipherOnly -- (7)
    | KeyUsage_decipherOnly -- (8)
    deriving (Show, Eq, Ord, Enum)

{-
-- RFC 5280
oidDistributionPoints, oidPolicies, oidPoliciesMapping :: OID
oidPolicies           = [2,5,29,32]
oidPoliciesMapping    = [2,5,29,33]
-}

-- | Extension class.
--
-- each extension have a unique OID associated, and a way
-- to encode and decode an ASN1 stream.
--
-- Errata: turns out, the content is not necessarily ASN1,
-- it could be data that is only parsable by the extension
-- e.g. raw ascii string. Add method to parse and encode with
-- ByteString
class Extension a where
    extOID :: a -> OID
    extHasNestedASN1 :: Proxy a -> Bool
    extEncode :: a -> [ASN1]
    extDecode :: [ASN1] -> Either String a

    extDecodeBs :: B.ByteString -> Either String a
    extDecodeBs = (safeDecode . decodeASN1' BER) >=> extDecode

    extEncodeBs :: a -> B.ByteString
    extEncodeBs = encodeASN1' DER . extEncode

-- | Get a specific extension from a lists of raw extensions
extensionGet :: Extension a => Extensions -> Maybe a
extensionGet (Extensions Nothing) = Nothing
extensionGet (Extensions (Just l)) = findExt l
  where
    findExt [] = Nothing
    findExt (x : xs) = case extensionDecode x of
        Just (Right e) -> Just e
        _ -> findExt xs

-- | Get a specific extension from a lists of raw extensions
extensionGetE :: Extension a => Extensions -> Maybe (Either String a)
extensionGetE (Extensions Nothing) = Nothing
extensionGetE (Extensions (Just l)) = findExt l
  where
    findExt [] = Nothing
    findExt (x : xs) = case extensionDecode x of
        Just r -> Just r
        _ -> findExt xs

-- | Try to decode an ExtensionRaw.
--
-- If this function return:
-- * Nothing, the OID doesn't match
-- * Just Left, the OID matched, but the extension couldn't be decoded
-- * Just Right, the OID matched, and the extension has been succesfully decoded
extensionDecode
    :: forall a. Extension a => ExtensionRaw -> Maybe (Either String a)
extensionDecode er@(ExtensionRaw oid _ content)
    | extOID (undefined :: a) /= oid = Nothing
    | extHasNestedASN1 (Proxy :: Proxy a) = Just (tryExtRawASN1 er >>= extDecode)
    | otherwise = Just (extDecodeBs content)

-- | Encode an Extension to extensionRaw
extensionEncode :: forall a. Extension a => Bool -> a -> ExtensionRaw
extensionEncode critical ext
    | extHasNestedASN1 (Proxy :: Proxy a) =
        ExtensionRaw (extOID ext) critical (encodeASN1' DER $ extEncode ext)
    | otherwise =
        ExtensionRaw (extOID ext) critical (extEncodeBs ext)

-- | Basic Constraints
data ExtBasicConstraints = ExtBasicConstraints Bool (Maybe Integer)
    deriving (Show, Eq)

instance Extension ExtBasicConstraints where
    extOID = const [2, 5, 29, 19]
    extHasNestedASN1 = const True
    extEncode (ExtBasicConstraints b Nothing) = [Start Sequence, Boolean b, End Sequence]
    extEncode (ExtBasicConstraints b (Just i)) = [Start Sequence, Boolean b, IntVal i, End Sequence]

    extDecode [Start Sequence, Boolean b, IntVal v, End Sequence]
        | v >= 0 = Right (ExtBasicConstraints b (Just v))
        | otherwise = Left "invalid pathlen"
    extDecode [Start Sequence, Boolean b, End Sequence] = Right (ExtBasicConstraints b Nothing)
    extDecode [Start Sequence, End Sequence] = Right (ExtBasicConstraints False Nothing)
    -- cA is omitted when FALSE (DER)
    extDecode [Start Sequence, IntVal v, End Sequence]
        | v >= 0 = Right (ExtBasicConstraints False (Just v))
        | otherwise = Left "invalid pathlen"
    extDecode _ = Left "unknown sequence"

-- | Describe key usage
data ExtKeyUsage = ExtKeyUsage [ExtKeyUsageFlag]
    deriving (Show, Eq)

instance Extension ExtKeyUsage where
    extOID = const [2, 5, 29, 15]
    extHasNestedASN1 = const True
    extEncode (ExtKeyUsage flags) = [BitString $ flagsToBits flags]
    extDecode [BitString bits] =
        Right $ ExtKeyUsage $ bitsToFlags KeyUsage_decipherOnly bits
    extDecode _ = Left "unknown sequence"

-- | Key usage purposes for the ExtendedKeyUsage extension
data ExtKeyUsagePurpose
    = KeyUsagePurpose_ServerAuth
    | KeyUsagePurpose_ClientAuth
    | KeyUsagePurpose_CodeSigning
    | KeyUsagePurpose_EmailProtection
    | KeyUsagePurpose_TimeStamping
    | KeyUsagePurpose_OCSPSigning
    | KeyUsagePurpose_Unknown OID
    deriving (Show, Eq, Ord)

extKeyUsagePurposedOID :: [(OID, ExtKeyUsagePurpose)]
extKeyUsagePurposedOID =
    [ (keyUsagePurposePrefix 1, KeyUsagePurpose_ServerAuth)
    , (keyUsagePurposePrefix 2, KeyUsagePurpose_ClientAuth)
    , (keyUsagePurposePrefix 3, KeyUsagePurpose_CodeSigning)
    , (keyUsagePurposePrefix 4, KeyUsagePurpose_EmailProtection)
    , (keyUsagePurposePrefix 8, KeyUsagePurpose_TimeStamping)
    , (keyUsagePurposePrefix 9, KeyUsagePurpose_OCSPSigning)
    ]
  where
    keyUsagePurposePrefix r = [1, 3, 6, 1, 5, 5, 7, 3, r]

-- | Extended key usage extension
data ExtExtendedKeyUsage = ExtExtendedKeyUsage [ExtKeyUsagePurpose]
    deriving (Show, Eq)

instance Extension ExtExtendedKeyUsage where
    extOID = const [2, 5, 29, 37]
    extHasNestedASN1 = const True
    extEncode (ExtExtendedKeyUsage purposes) =
        [Start Sequence] ++ map (OID . lookupRev) purposes ++ [End Sequence]
      where
        lookupRev (KeyUsagePurpose_Unknown oid) = oid
        lookupRev kup =
            maybe (error "unknown key usage purpose") fst $
                find ((==) kup . snd) extKeyUsagePurposedOID
    extDecode l =
        ExtExtendedKeyUsage
            `fmap` ( flip runParseASN1 l $ onNextContainer Sequence $ getMany $ do
                        n <- getNext
                        case n of
                            OID o ->
                                return $ maybe (KeyUsagePurpose_Unknown o) id $ lookup o extKeyUsagePurposedOID
                            _ -> throwParseError "invalid content in extended key usage"
                   )

-- | Provide a way to identify a public key by a short hash.
data ExtSubjectKeyId = ExtSubjectKeyId B.ByteString
    deriving (Show, Eq)

instance Extension ExtSubjectKeyId where
    extOID = const [2, 5, 29, 14]
    extHasNestedASN1 = const True
    extEncode (ExtSubjectKeyId o) = [OctetString o]
    extDecode [OctetString o] = Right $ ExtSubjectKeyId o
    extDecode _ = Left "unknown sequence"

-- | Different naming scheme use by the extension.
--
-- Not all name types are available, missing:
-- otherName
-- x400Address
-- ediPartyName
-- registeredID
data AltName
    = AltNameRFC822 String
    | AltNameDNS String
    | AltNameDN DistinguishedName
    | AltNameURI String
    | AltNameIP B.ByteString
    | AltNameXMPP String
    | AltNameDNSSRV String
    deriving (Show, Eq, Ord)

-- | Provide a way to supply alternate name that can be
-- used for matching host name.
data ExtSubjectAltName = ExtSubjectAltName [AltName]
    deriving (Show, Eq, Ord)

instance Extension ExtSubjectAltName where
    extOID = const [2, 5, 29, 17]
    extHasNestedASN1 = const True
    extEncode (ExtSubjectAltName names) = encodeGeneralNames names
    extDecode l = runParseASN1 (ExtSubjectAltName <$> parseGeneralNames) l

-- | Provide a mean to identify the public key corresponding to the private key
-- used to signed a certificate.
data ExtAuthorityKeyId = ExtAuthorityKeyId B.ByteString
    deriving (Show, Eq)

instance Extension ExtAuthorityKeyId where
    extOID _ = [2, 5, 29, 35]
    extHasNestedASN1 = const True
    extEncode (ExtAuthorityKeyId keyid) =
        [Start Sequence, Other Context 0 keyid, End Sequence]

    -- authorityCertIssuer and authorityCertSerialNumber are not kept
    extDecode (Start Sequence : Other Context 0 keyid : rest)
        | issuerSerial rest = Right $ ExtAuthorityKeyId keyid
      where
        issuerSerial [End Sequence] = True
        issuerSerial (Start (Container Context 1) : xs) =
            case dropWhile (/= End (Container Context 1)) xs of
                _ : [Other Context 2 _, End Sequence] -> True
                _ -> False
        issuerSerial _ = False
    extDecode _ = Left "unknown sequence"

-- | Identify how CRL information is obtained
data ExtCrlDistributionPoints = ExtCrlDistributionPoints [DistributionPoint]
    deriving (Show, Eq)

-- | Reason flag for the CRL
data ReasonFlag
    = Reason_Unused
    | Reason_KeyCompromise
    | Reason_CACompromise
    | Reason_AffiliationChanged
    | Reason_Superseded
    | Reason_CessationOfOperation
    | Reason_CertificateHold
    | Reason_PrivilegeWithdrawn
    | Reason_AACompromise
    deriving (Show, Eq, Ord, Enum)

-- | Distribution point as either some GeneralNames or a DN
data DistributionPoint
    = DistributionPointFullName [AltName]
    | DistributionNameRelative DistinguishedName
    deriving (Show, Eq)

instance Extension ExtCrlDistributionPoints where
    extOID _ = [2, 5, 29, 31]
    extHasNestedASN1 = const True
    extEncode = error "extEncode ExtCrlDistributionPoints unimplemented"
    extDecode _ = Left "extDecode ExtCrlDistributionPoints unimplemented"

-- extEncode (ExtCrlDistributionPoints )

-- | GeneralName types that 'AltName' cannot represent are skipped.
parseGeneralNames :: ParseASN1 [AltName]
parseGeneralNames = onNextContainer Sequence $ do
    names <- catMaybes <$> getMany getAddrMaybe
    forM_ names $ \name -> case name of
        AltNameIP ip
            | B.length ip /= 4 && B.length ip /= 16 ->
                throwParseError "GeneralNames: invalid iPAddress length"
        _ -> return ()
    return names

-- | Fails on GeneralName types that 'AltName' cannot represent.
getAddr :: ParseASN1 AltName
getAddr =
    getAddrMaybe
        >>= maybe (throwParseError "GeneralNames: unsupported name type") return

-- | 'Nothing' for a well-formed GeneralName of an unsupported type.
getAddrMaybe :: ParseASN1 (Maybe AltName)
getAddrMaybe = do
    m <- onNextContainerMaybe (Container Context 0) getComposedAddr
    case m of
        Just r -> return r
        Nothing -> do
            d <- onNextContainerMaybe (Container Context 4) getObject
            case d of
                Just dn -> return $ Just $ AltNameDN dn
                Nothing -> getUnsupportedOrSimpleAddr
  where
    getComposedAddr = do
        n <- getNext
        case n of
            OID [1, 3, 6, 1, 5, 5, 7, 8, 5] -> do
                -- xmpp addr
                c <- getNextContainerMaybe (Container Context 0)
                case c of
                    Just [ASN1String cs] ->
                        case safeCharacterToString cs of
                            Nothing -> throwParseError ("GeneralNames: invalid string for XMPP Addr")
                            Just s -> return $ Just $ AltNameXMPP s
                    _ ->
                        throwParseError ("GeneralNames: expecting string for XMPP Addr got: " ++ show c)
            OID [1, 3, 6, 1, 5, 5, 7, 8, 7] -> do
                -- DNSSRV addr
                c <- getNextContainerMaybe (Container Context 0)
                case c of
                    Just [ASN1String cs] ->
                        case safeCharacterToString cs of
                            Nothing -> throwParseError ("GeneralNames: invalid string for DNSSrv Addr")
                            Just s -> return $ Just $ AltNameDNSSRV s
                    _ ->
                        throwParseError
                            ("GeneralNames: expecting string for DNSSRV Addr got: " ++ show c)
            OID _ -> getMany getNext >> return Nothing -- unknown otherName
            _ -> throwParseError ("GeneralNames: expecting OID but got " ++ show n)

    getSimpleAddr = do
        n <- getNext
        case n of
            (Other Context 1 b) -> return $ Just $ AltNameRFC822 $ BC.unpack b
            (Other Context 2 b) -> return $ Just $ AltNameDNS $ BC.unpack b
            -- directoryName as written by older versions of this library
            (Other Context 4 b) -> case safeDecode (decodeASN1' DER b) of
                Left e1 -> throwParseError e1
                Right as -> case runParseASN1 getObject as of
                    Right dn -> return $ Just $ AltNameDN dn
                    Left e2 -> throwParseError e2
            (Other Context 6 b) -> return $ Just $ AltNameURI $ BC.unpack b
            (Other Context 7 b) -> return $ Just $ AltNameIP b
            (Other Context 8 _) -> return Nothing -- registeredID
            _ ->
                throwParseError ("GeneralNames: not coping with unknown stream " ++ show n)
    -- x400Address and ediPartyName are skipped
    getUnsupportedOrSimpleAddr = do
        x400 <- getNextContainerMaybe (Container Context 3)
        edi <- maybe (getNextContainerMaybe (Container Context 5)) (return . Just) x400
        maybe getSimpleAddr (const $ return Nothing) edi

encodeGeneralNames :: [AltName] -> [ASN1]
encodeGeneralNames names =
    [Start Sequence]
        ++ concatMap encodeAltName names
        ++ [End Sequence]

encodeAltName :: AltName -> [ASN1]
encodeAltName (AltNameRFC822 n) = [Other Context 1 $ BC.pack n]
encodeAltName (AltNameDNS n) = [Other Context 2 $ BC.pack n]
encodeAltName (AltNameDN dn) =
    [Start (Container Context 4)] ++ toASN1 dn [End (Container Context 4)]
encodeAltName (AltNameURI n) = [Other Context 6 $ BC.pack n]
encodeAltName (AltNameIP n) = [Other Context 7 $ n]
encodeAltName (AltNameXMPP n) =
    [ Start (Container Context 0)
    , OID [1, 3, 6, 1, 5, 5, 7, 8, 5]
    , Start (Container Context 0)
    , ASN1String $ asn1CharacterString UTF8 n
    , End (Container Context 0)
    , End (Container Context 0)
    ]
encodeAltName (AltNameDNSSRV n) =
    [ Start (Container Context 0)
    , OID [1, 3, 6, 1, 5, 5, 7, 8, 7]
    , Start (Container Context 0)
    , ASN1String $ asn1CharacterString UTF8 n
    , End (Container Context 0)
    , End (Container Context 0)
    ]

-- | Bits beyond the last known flag (the first argument) or beyond the
-- actual data (a bogus length) are ignored.
bitsToFlags :: Enum a => a -> BitArray -> [a]
bitsToFlags lastFlag bits =
    [toEnum (fromIntegral i) | len > 0, i <- [0 .. len - 1], bitArrayGetBit bits i]
  where
    dataLen = 8 * fromIntegral (B.length (bitArrayGetData bits))
    len = minimum [bitArrayLength bits, dataLen, fromIntegral (fromEnum lastFlag) + 1]

-- | DER: trailing zero bits are removed.
flagsToBits :: Enum a => [a] -> BitArray
flagsToBits flags = toBitArray (B.pack bytes) (8 * nbytes - len)
  where
    ixs = map fromEnum flags
    len = if null ixs then 0 else maximum ixs + 1
    nbytes = (len + 7) `div` 8
    bytes =
        [ foldl (.|.) 0 [bit (7 - i `mod` 8) | i <- ixs, i `div` 8 == n]
        | n <- [0 .. nbytes - 1]
        ]

data ExtNetscapeComment = ExtNetscapeComment B.ByteString
    deriving (Show, Eq)

instance Extension ExtNetscapeComment where
    extOID _ = [2, 16, 840, 1, 113730, 1, 13]
    extHasNestedASN1 = const False
    extEncode = error "Extension: Netscape Comment do not contain nested ASN1"
    extDecode = error "Extension: Netscape Comment do not contain nested ASN1"
    extEncodeBs (ExtNetscapeComment b) = b
    extDecodeBs = Right . ExtNetscapeComment

--------------------------------------------------------------------------------
-- RFC5280
--
-- NameConstraints ::= SEQUENCE {
--      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
--      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL
-- }
--
-- GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
--
-- GeneralSubtree ::= SEQUENCE {
--      base                    GeneralName,
--      minimum         [0]     BaseDistance DEFAULT 0,
--      maximum         [1]     BaseDistance OPTIONAL
-- }
--------------------------------------------------------------------------------

data GeneralSubtree = GeneralSubtree AltName Integer (Maybe Integer)
    deriving (Show, Eq)

data ExtNameConstraints = ExtNameConstraints [GeneralSubtree] [GeneralSubtree]
    deriving (Show, Eq)

instance Extension ExtNameConstraints where
    extOID _ = [2, 5, 29, 30]
    extHasNestedASN1 _ = True
    extEncode = encodeNameConstraints
    extDecode = decodeNameConstraints

--------------------------------------------------------------------------------
-- Encoding
--------------------------------------------------------------------------------

encodeNameConstraints :: ExtNameConstraints -> [ASN1]
encodeNameConstraints (ExtNameConstraints permitted excluded) =
    [Start Sequence]
        ++ put 0 permitted
        ++ put 1 excluded
        ++ [End Sequence]
  where
    put _ [] = []
    -- IMPLICIT tagging: the tag replaces the SEQUENCE OF
    put n xs =
        [Start (Container Context n)]
            ++ concatMap encodeGeneralSubtree xs
            ++ [End (Container Context n)]

encodeGeneralSubtree :: GeneralSubtree -> [ASN1]
encodeGeneralSubtree (GeneralSubtree base minimum' maximum') =
    [Start Sequence]
        ++ encodeAltName base
        ++ (if minimum' /= 0 then [Other Context 0 (intContent minimum')] else [])
        ++ maybe [] (\m -> [Other Context 1 (intContent m)]) maximum'
        ++ [End Sequence]
  where
    -- the content octets of an IMPLICIT INTEGER (two's complement)
    intContent = B.pack . go
      where
        go i
            | i >= -128 && i < 128 = [fromIntegral i]
            | otherwise = go (i `shiftR` 8) ++ [fromIntegral (i .&. 0xff)]

--------------------------------------------------------------------------------
-- Decoding
--------------------------------------------------------------------------------

decodeNameConstraints :: [ASN1] -> Either String ExtNameConstraints
decodeNameConstraints
    (Start Sequence : xs) =
        go xs [] []
      where
        go (End Sequence : _) permitted excluded =
            Right $ ExtNameConstraints permitted excluded
        go (Start (Container Context 0) : rest) _ excluded = do
            (subs, rest') <- decodeSubtrees rest
            go rest' subs excluded
        go (Start (Container Context 1) : rest) permitted _ = do
            (subs, rest') <- decodeSubtrees rest
            go rest' permitted subs
        go _ _ _ = Left "Invalid NameConstraints"
        decodeSubtrees :: [ASN1] -> Either String ([GeneralSubtree], [ASN1])
        decodeSubtrees ys = loop ys []
          where
            loop (End (Container Context _) : _) [] =
                Left "NameConstraints: empty GeneralSubtrees"
            loop (End (Container Context _) : rest) acc =
                Right (reverse acc, rest)
            loop zs acc = do
                (s, zs') <- decodeGeneralSubtree zs
                loop zs' (s : acc)
decodeNameConstraints _ =
    Left "NameConstraints: expected SEQUENCE"

decodeGeneralSubtree
    :: [ASN1]
    -> Either String (GeneralSubtree, [ASN1])
decodeGeneralSubtree (Start Sequence : xs) = do
    (base, rest1) <- runParseASN1State getAddr xs
    -- an iPAddress constraint is an address followed by a mask
    case base of
        AltNameIP ip
            | B.length ip /= 8 && B.length ip /= 32 ->
                Left "GeneralSubtree: invalid iPAddress length"
        _ -> Right ()

    (minimum', rest2) <- case rest1 of
        (Other Context 0 bs : rs) -> (\n -> (n, rs)) <$> implicitInt bs
        _ -> Right (0, rest1)
    (maximum', rest3) <- case rest2 of
        (Other Context 1 bs : rs) -> (\n -> (Just n, rs)) <$> implicitInt bs
        _ -> Right (Nothing, rest2)

    case rest3 of
        (End Sequence : rs) ->
            Right (GeneralSubtree base minimum' maximum', rs)
        _ ->
            Left "GeneralSubtree: missing end sequence"
decodeGeneralSubtree _ =
    Left "GeneralSubtree: invalid ASN1"

-- | Decode the content octets of an IMPLICIT INTEGER.
implicitInt :: B.ByteString -> Either String Integer
implicitInt bs
    | B.null bs = Left "GeneralSubtree: empty integer"
    | otherwise = Right $ B.foldl' (\a w -> a * 256 + fromIntegral w) sign bs
  where
    sign = if testBit (B.head bs) 7 then -1 else 0

recognizedOIDs :: [OID]
recognizedOIDs =
    [ [2, 5, 29, 19] -- ExtBasicConstraints
    , [2, 5, 29, 15] -- ExtKeyUsage
    , [2, 5, 29, 37] -- ExtExtendedKeyUsage
    , [2, 5, 29, 14] -- ExtSubjectKeyId
    , [2, 5, 29, 17] -- ExtSubjectAltName
    , [2, 5, 29, 35] -- ExtAuthorityKeyId
    , [2, 5, 29, 31] -- ExtCrlDistributionPoints
    , [2, 5, 29, 30] -- ExtNameConstraints
    , [2, 16, 840, 1, 113730, 1, 13] -- ExtNetscapeComment
    ]
