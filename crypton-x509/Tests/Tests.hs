{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Test.Tasty
import Test.Tasty.QuickCheck

import qualified Data.ByteString as B

import Control.Monad

import Crypto.Debug (DebugShow (..))
import Crypto.Error (throwCryptoError)
import Crypto.Number.Serialize (i2ospOf_)
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.MLDSA as MLDSA
import qualified Crypto.PubKey.MLKEM as MLKEM
import qualified Crypto.PubKey.RSA as RSA
import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.BitArray (toBitArray)
import Data.ASN1.Encoding (decodeASN1', encodeASN1')
import Data.ASN1.Types
import Data.ByteArray (convert)
import Data.List (isInfixOf, nub, sort)
import Data.Maybe (fromJust)
import Data.Proxy (Proxy (..))
import Data.X509
import Data.X509.EC (ecPubKeyCurveName)

import MLDSAKeys
import MLKEMKeys

import Data.Hourglass

instance Arbitrary RSA.PublicKey where
    arbitrary = do
        bytes <- elements [64, 128, 256]
        e <- elements [0x3, 0x10001]
        n <- choose (2 ^ (8 * (bytes - 1)), 2 ^ (8 * bytes))
        return $
            RSA.PublicKey
                { RSA.public_size = bytes
                , RSA.public_n = n
                , RSA.public_e = e
                }

instance Arbitrary DSA.Params where
    arbitrary = DSA.Params <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary DSA.PublicKey where
    arbitrary = DSA.PublicKey <$> arbitrary <*> arbitrary

instance Arbitrary X25519.PublicKey where
    arbitrary = X25519.toPublic <$> arbitrary

instance Arbitrary X448.PublicKey where
    arbitrary = X448.toPublic <$> arbitrary

instance Arbitrary Ed25519.PublicKey where
    arbitrary = Ed25519.toPublic <$> arbitrary

instance Arbitrary Ed448.PublicKey where
    arbitrary = Ed448.toPublic <$> arbitrary

instance Arbitrary PubKey where
    arbitrary =
        oneof
            [ PubKeyRSA <$> arbitrary
            , PubKeyRSAPSS <$> arbitrary <*> arbitraryKeyPSS
            , PubKeyDSA <$> arbitrary
            , PubKeyDH <$> arbitraryDH
            , -- , PubKeyECDSA ECDSA_Hash_SHA384 <$> (B.pack <$> replicateM 384 arbitrary)
              PubKeyX25519 <$> arbitrary
            , PubKeyX448 <$> arbitrary
            , PubKeyEd25519 <$> arbitrary
            , PubKeyEd448 <$> arbitrary
            , PubKeyMLDSA44 . MLDSA.toPublic <$> arbitraryMLDSA (Proxy :: Proxy MLDSA.MLDSA44)
            , PubKeyMLDSA65 . MLDSA.toPublic <$> arbitraryMLDSA (Proxy :: Proxy MLDSA.MLDSA65)
            , PubKeyMLDSA87 . MLDSA.toPublic <$> arbitraryMLDSA (Proxy :: Proxy MLDSA.MLDSA87)
            , PubKeyMLKEM512 . fst <$> arbitraryMLKEM (Proxy :: Proxy MLKEM.MLKEM512)
            , PubKeyMLKEM768 . fst <$> arbitraryMLKEM (Proxy :: Proxy MLKEM.MLKEM768)
            , PubKeyMLKEM1024 . fst <$> arbitraryMLKEM (Proxy :: Proxy MLKEM.MLKEM1024)
            ]

arbitraryKeyPSS :: Gen (Maybe PSSParams)
arbitraryKeyPSS =
    oneof
        [ pure Nothing
        , (\h m s -> Just (defaultPSSParams h){pssMGFHash = m, pssSaltLength = s})
            <$> hash
            <*> hash
            <*> choose (0, 64)
        ]
  where
    hash =
        elements
            [ HashSHA1
            , HashSHA224
            , HashSHA256
            , HashSHA384
            , HashSHA512
            , HashSHA3_256
            , HashSHA3_512
            ]

arbitraryDH :: Gen PubKeyDH
arbitraryDH = do
    k <- dhPublicKey <$> pos <*> pos <*> pos <*> pos
    j <- oneof [pure Nothing, Just <$> pos]
    v <-
        oneof
            [ pure Nothing
            , (\s c -> Just (toBitArray (B.pack s) 0, c)) <$> arbitrary <*> pos
            ]
    return k{pubkeyDH_j = j, pubkeyDH_validation = v}
  where
    pos = getPositive <$> arbitrary

instance Arbitrary RSA.PrivateKey where
    arbitrary =
        RSA.PrivateKey
            <$> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary DSA.PrivateKey where
    arbitrary = DSA.PrivateKey <$> arbitrary <*> arbitrary

instance Arbitrary X25519.SecretKey where
    arbitrary = throwCryptoError . X25519.secretKey <$> arbitraryBS 32 32

instance Arbitrary X448.SecretKey where
    arbitrary = throwCryptoError . X448.secretKey <$> arbitraryBS 56 56

instance Arbitrary Ed25519.SecretKey where
    arbitrary = throwCryptoError . Ed25519.secretKey <$> arbitraryBS 32 32

instance Arbitrary Ed448.SecretKey where
    arbitrary = throwCryptoError . Ed448.secretKey <$> arbitraryBS 57 57

instance Arbitrary PrivKey where
    arbitrary =
        oneof
            [ PrivKeyRSA <$> arbitrary
            , PrivKeyRSAPSS <$> arbitrary <*> arbitraryKeyPSS
            , PrivKeyDSA <$> arbitrary
            , -- , PrivKeyECDSA ECDSA_Hash_SHA384 <$> (B.pack <$> replicateM 384 arbitrary)
              PrivKeyX25519 <$> arbitrary
            , PrivKeyX448 <$> arbitrary
            , PrivKeyEd25519 <$> arbitrary
            , PrivKeyEd448 <$> arbitrary
            , PrivKeyMLDSA44 <$> arbitraryPrivMLDSA (Proxy :: Proxy MLDSA.MLDSA44)
            , PrivKeyMLDSA65 <$> arbitraryPrivMLDSA (Proxy :: Proxy MLDSA.MLDSA65)
            , PrivKeyMLDSA87 <$> arbitraryPrivMLDSA (Proxy :: Proxy MLDSA.MLDSA87)
            , PrivKeyMLKEM512 <$> arbitraryPrivMLKEM (Proxy :: Proxy MLKEM.MLKEM512)
            , PrivKeyMLKEM768 <$> arbitraryPrivMLKEM (Proxy :: Proxy MLKEM.MLKEM768)
            , PrivKeyMLKEM1024 <$> arbitraryPrivMLKEM (Proxy :: Proxy MLKEM.MLKEM1024)
            ]

arbitraryMLKEM
    :: MLKEM.MLKEM p
    => proxy p -> Gen (MLKEM.EncapsulationKey p, MLKEM.DecapsulationKey p)
arbitraryMLKEM p = throwCryptoError . MLKEM.keyPairFromSeed p <$> arbitraryBS 64 64

arbitraryPrivMLKEM :: MLKEM.MLKEM p => proxy p -> Gen (PrivKeyMLKEM p)
arbitraryPrivMLKEM p = do
    form <- elements [MLKeySeed, MLKeyExpanded, MLKeyBoth]
    throwCryptoError . privkeyMLKEMFromSeed p form <$> arbitraryBS 64 64

arbitraryMLDSA :: MLDSA.MLDSA p => proxy p -> Gen (MLDSA.SigningKey p)
arbitraryMLDSA p = snd . throwCryptoError . MLDSA.keyPairFromSeed p <$> arbitraryBS 32 32

-- | All three forms are generated, so that the marshalling round trip
-- covers each of them and not just whichever one this module would pick.
arbitraryPrivMLDSA :: MLDSA.MLDSA p => proxy p -> Gen (PrivKeyMLDSA p)
arbitraryPrivMLDSA p = do
    form <- elements [MLKeySeed, MLKeyExpanded, MLKeyBoth]
    throwCryptoError . privkeyMLDSAFromSeed p form <$> arbitraryBS 32 32

instance Arbitrary HashALG where
    arbitrary =
        elements
            [ HashMD2
            , HashMD5
            , HashSHA1
            , HashSHA224
            , HashSHA256
            , HashSHA384
            , HashSHA512
            , HashSHA3_224
            , HashSHA3_256
            , HashSHA3_384
            , HashSHA3_512
            ]

instance Arbitrary PubKeyALG where
    arbitrary = elements [PubKeyALG_RSA, PubKeyALG_DSA, PubKeyALG_EC, PubKeyALG_DH]

instance Arbitrary SignatureALG where
    -- unfortunately as the encoding of this is a single OID as opposed to two OID,
    -- the testing need to limit itself to Signature ALG that has been defined in the OID database.
    -- arbitrary = SignatureALG <$> arbitrary <*> arbitrary
    arbitrary =
        elements
            [ SignatureALG HashSHA1 PubKeyALG_RSA
            , SignatureALG HashMD5 PubKeyALG_RSA
            , SignatureALG HashMD2 PubKeyALG_RSA
            , SignatureALG HashSHA256 PubKeyALG_RSA
            , SignatureALG HashSHA384 PubKeyALG_RSA
            , SignatureALG HashSHA512 PubKeyALG_RSA
            , SignatureALG HashSHA224 PubKeyALG_RSA
            , SignatureALG HashSHA1 PubKeyALG_DSA
            , SignatureALG HashSHA224 PubKeyALG_DSA
            , SignatureALG HashSHA256 PubKeyALG_DSA
            , SignatureALG HashSHA224 PubKeyALG_EC
            , SignatureALG HashSHA256 PubKeyALG_EC
            , SignatureALG HashSHA384 PubKeyALG_EC
            , SignatureALG HashSHA512 PubKeyALG_EC
            , SignatureALG HashSHA3_224 PubKeyALG_RSA
            , SignatureALG HashSHA3_256 PubKeyALG_RSA
            , SignatureALG HashSHA3_384 PubKeyALG_RSA
            , SignatureALG HashSHA3_512 PubKeyALG_RSA
            , SignatureALG HashSHA3_224 PubKeyALG_DSA
            , SignatureALG HashSHA3_256 PubKeyALG_DSA
            , SignatureALG HashSHA3_384 PubKeyALG_DSA
            , SignatureALG HashSHA3_512 PubKeyALG_DSA
            , SignatureALG HashSHA3_224 PubKeyALG_EC
            , SignatureALG HashSHA3_256 PubKeyALG_EC
            , SignatureALG HashSHA3_384 PubKeyALG_EC
            , SignatureALG HashSHA3_512 PubKeyALG_EC
            , SignatureALG_IntrinsicHash PubKeyALG_Ed25519
            , SignatureALG_IntrinsicHash PubKeyALG_Ed448
            , SignatureALG_IntrinsicHash PubKeyALG_MLDSA44
            , SignatureALG_IntrinsicHash PubKeyALG_MLDSA65
            , SignatureALG_IntrinsicHash PubKeyALG_MLDSA87
            ]

arbitraryBS r1 r2 = choose (r1, r2) >>= \l -> (B.pack <$> replicateM l arbitrary)

instance Arbitrary ASN1StringEncoding where
    arbitrary = elements [IA5, UTF8]

instance Arbitrary ASN1CharacterString where
    arbitrary = ASN1CharacterString <$> arbitrary <*> arbitraryBS 2 36

instance Arbitrary DistinguishedName where
    arbitrary = DistinguishedName <$> (choose (1, 5) >>= \l -> replicateM l arbitraryDE)
      where
        arbitraryDE = (,) <$> arbitrary <*> arbitrary

instance Arbitrary DateTime where
    arbitrary = timeConvert <$> (arbitrary :: Gen Elapsed)
instance Arbitrary Elapsed where
    arbitrary = Elapsed . Seconds <$> (choose (1, 100000000))

instance Arbitrary Extensions where
    arbitrary =
        Extensions
            <$> oneof
                [ pure Nothing
                , Just
                    -- at most one instance of an extension
                    <$> ( (: [])
                            <$> (extensionEncode <$> arbitrary <*> (arbitrary :: Gen ExtKeyUsage))
                        )
                ]

instance Arbitrary ExtKeyUsageFlag where
    arbitrary = elements $ enumFrom KeyUsage_digitalSignature
instance Arbitrary ExtKeyUsage where
    arbitrary = ExtKeyUsage . sort . nub <$> listOf1 arbitrary

instance Arbitrary ExtKeyUsagePurpose where
    arbitrary =
        elements
            [ KeyUsagePurpose_ServerAuth
            , KeyUsagePurpose_ClientAuth
            , KeyUsagePurpose_CodeSigning
            , KeyUsagePurpose_EmailProtection
            , KeyUsagePurpose_TimeStamping
            , KeyUsagePurpose_OCSPSigning
            ]
instance Arbitrary ExtExtendedKeyUsage where
    arbitrary = ExtExtendedKeyUsage . nub <$> listOf1 arbitrary

instance Arbitrary Certificate where
    arbitrary =
        Certificate
            <$> pure 2
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary RevokedCertificate where
    arbitrary =
        RevokedCertificate
            <$> arbitrary
            <*> arbitrary
            <*> arbitrary

instance Arbitrary CRL where
    arbitrary =
        CRL
            <$> pure 1
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary
            <*> arbitrary

property_unmarshall_marshall_id
    :: (Show o, Arbitrary o, ASN1Object o, Eq o) => o -> Bool
property_unmarshall_marshall_id o =
    case got of
        Right (gotObject, [])
            | gotObject == o -> True
            | otherwise ->
                error ("object is different: " ++ show gotObject ++ " expecting " ++ show o)
        Right (gotObject, l) ->
            error
                ( "state remaining: "
                    ++ show l
                    ++ " marshalled: "
                    ++ show oMarshalled
                    ++ " parsed: "
                    ++ show gotObject
                )
        Left e ->
            error
                ( "parsing failed: "
                    ++ show e
                    ++ " object: "
                    ++ show o
                    ++ " marshalled as: "
                    ++ show oMarshalled
                )
  where
    got = fromASN1 oMarshalled
    oMarshalled = toASN1 o []

-- | A scalar long enough that finding it in the rendered key cannot be an
-- accident of the curve parameters beside it.
newtype ECSecret = ECSecret Integer
    deriving (Show)

instance Arbitrary ECSecret where
    arbitrary = ECSecret <$> choose (10 ^ (40 :: Int), 10 ^ (41 :: Int))

-- | 'show' of an EC private key holds the curve and not the scalar, and
-- 'debugShow' holds both.  The wrapper is checked too, since it is
-- @Credential@ and @ServerParams@ that a program actually prints.
property_ec_show_redacts :: ECSecret -> Bool
property_ec_show_redacts (ECSecret d) = all ok [named, prime]
  where
    named = PrivKeyEC_Named ECC.SEC_p256r1 d
    prime = PrivKeyEC_Prime d 1 2 3 (SerializedPoint B.empty) 4 1 5
    digits = show d
    ok k =
        not (digits `isInfixOf` show k)
            && not (digits `isInfixOf` show (PrivKeyEC k))
            && "<secret>" `isInfixOf` show k
            && digits `isInfixOf` debugShow k
            && digits `isInfixOf` debugShow (PrivKeyEC k)

-- | RFC 9881 Section 6: an ML-DSA-44 private key in PKCS#8 is the seed,
-- tagged [0], the expanded key, or both.  All three give one signing key,
-- and each is written back out as what it was read as.
newtype MLDSASeed = MLDSASeed B.ByteString deriving (Show)

instance Arbitrary MLDSASeed where
    arbitrary = MLDSASeed <$> arbitraryBS 32 32

mldsaPKCS8ASN1 :: [ASN1] -> [ASN1]
mldsaPKCS8ASN1 inner =
    [ Start Sequence
    , IntVal 0
    , Start Sequence
    , OID [2, 16, 840, 1, 101, 3, 4, 3, 17]
    , End Sequence
    , OctetString (encodeASN1' DER inner)
    , End Sequence
    ]

mldsaPKCS8 :: [ASN1] -> Either String (PrivKey, [ASN1])
mldsaPKCS8 = fromASN1 . mldsaPKCS8ASN1

mldsaExpanded :: B.ByteString -> B.ByteString
mldsaExpanded seed =
    convert $
        snd $
            throwCryptoError $
                MLDSA.keyPairFromSeed (Proxy :: Proxy MLDSA.MLDSA44) seed

-- | The three encodings of one seed, with the form each of them is.
mldsaForms :: B.ByteString -> [(MLKeyForm, [ASN1])]
mldsaForms seed =
    [ (MLKeySeed, [Other Context 0 seed])
    , (MLKeyExpanded, [OctetString expanded])
    ,
        ( MLKeyBoth
        , [Start Sequence, OctetString seed, OctetString expanded, End Sequence]
        )
    ]
  where
    expanded = mldsaExpanded seed

-- | Each form parses, and all three carry the one signing key the seed
-- expands to.  The forms themselves stay apart: the parsed keys are three
-- different values, because they are three different files.
property_mldsa_forms :: MLDSASeed -> Bool
property_mldsa_forms (MLDSASeed seed) =
    map (fmap fst . mldsaPKCS8 . snd) (mldsaForms seed)
        == map (Right . expected) forms
        && length (nub (map expected forms)) == 3
  where
    forms = map fst (mldsaForms seed)
    expected form =
        PrivKeyMLDSA44 $
            throwCryptoError $
                privkeyMLDSAFromSeed (Proxy :: Proxy MLDSA.MLDSA44) form seed

-- | Reading a key and writing it again gives back the bytes it came from,
-- for each of the three forms.  This is what keeping the form is for: a
-- key store that rewrites a file must not turn a seed into an expanded key
-- behind the owner's back.
property_mldsa_form_round_trip :: MLDSASeed -> Bool
property_mldsa_form_round_trip (MLDSASeed seed) = all ok (mldsaForms seed)
  where
    ok (form, inner) = case mldsaPKCS8 inner of
        Right (k, []) ->
            toASN1 k [] == mldsaPKCS8ASN1 inner
                && formOf k == Just form
        _ -> False
    formOf (PrivKeyMLDSA44 k) = Just (privkeyMLDSA_form k)
    formOf _ = Nothing

-- | The seed caught at generation, written out and read back.
--
-- This is the whole point of the two halves: @crypton@'s
-- 'MLDSA.generateKeyPairAndSeed' is the only way to keep the seed a key was
-- made from, and the seed form of RFC 9881 Section 6 is where it goes.
-- Nothing else here generates a key, so without this the two never meet.
--
-- The key the seed expands to is the one that was generated, the file reads
-- back as what was written, and the file is shorter than the expanded key
-- alone -- which is what writing the seed is for.
property_mldsa_generated_seed :: Property
property_mldsa_generated_seed = ioProperty $ do
    (_, sk, seed) <- MLDSA.generateKeyPairAndSeed p
    let k = throwCryptoError $ privkeyMLDSAFromSeed p MLKeySeed seed
        privkey = PrivKeyMLDSA44 k
        encoded = toASN1 privkey []
    return $
        privkeyMLDSA_key k == sk
            && fromASN1 encoded == Right (privkey, [])
            && B.length (encodeASN1' DER encoded) < B.length (convert sk :: B.ByteString)
  where
    p = Proxy :: Proxy MLDSA.MLDSA44

-- | What another implementation writes, this one reads and writes back.
--
-- Everything else here encodes with this library and decodes with it again,
-- which says the two halves agree and nothing about the bytes.  These keys
-- were made by OpenSSL 3.6.4, so they say what no round trip can: that a
-- PKCS#8 from the rest of the world parses, and that what goes back out is
-- byte for byte what came in.
--
-- OpenSSL writes the @both@ form, which is also the case that has something
-- to check -- the expanded key must be what the seed expands to, or the
-- parse is refused.
property_mldsa_openssl :: Bool
property_mldsa_openssl = all ok keys
  where
    keys =
        [ (opensslMLDSA44, "ML-DSA-44")
        , (opensslMLDSA65, "ML-DSA-65")
        , (opensslMLDSA87, "ML-DSA-87")
        ]
    ok (der, _) = case decodeASN1' DER der of
        Left _ -> False
        Right asn1 -> case fromASN1 asn1 :: Either String (PrivKey, [ASN1]) of
            Right (k, []) ->
                formOf k == Just MLKeyBoth
                    && encodeASN1' DER (toASN1 k []) == der
            _ -> False
    formOf (PrivKeyMLDSA44 k) = Just (privkeyMLDSA_form k)
    formOf (PrivKeyMLDSA65 k) = Just (privkeyMLDSA_form k)
    formOf (PrivKeyMLDSA87 k) = Just (privkeyMLDSA_form k)
    formOf _ = Nothing

-- | 'show' of an ML-DSA private key holds neither the seed nor the key,
-- and 'debugShow' holds both.
property_mldsa_show_redacts :: MLDSASeed -> Bool
property_mldsa_show_redacts (MLDSASeed seed) = all ok (map fst (mldsaForms seed))
  where
    hex = concatMap byte . B.unpack
    byte w = [digit (w `div` 16), digit (w `mod` 16)]
    digit n = "0123456789abcdef" !! fromIntegral n
    ok form =
        let k =
                throwCryptoError $
                    privkeyMLDSAFromSeed (Proxy :: Proxy MLDSA.MLDSA44) form seed
            wrapped = PrivKeyMLDSA44 k
            shown = show k ++ show wrapped
            debugged = debugShow k ++ debugShow wrapped
            expanded = hex (mldsaExpanded seed)
         in not (hex seed `isInfixOf` shown)
                && not (expanded `isInfixOf` shown)
                && expanded `isInfixOf` debugged
                && (form == MLKeyExpanded || hex seed `isInfixOf` debugged)

property_mldsa_mismatch :: MLDSASeed -> MLDSASeed -> Property
property_mldsa_mismatch (MLDSASeed seed1) (MLDSASeed seed2) =
    seed1 /= seed2 ==>
        either (const True) (const False) $
            mldsaPKCS8
                [ Start Sequence
                , OctetString seed1
                , OctetString (mldsaExpanded seed2)
                , End Sequence
                ]

instance Arbitrary AltName where
    arbitrary =
        oneof
            [ AltNameDNS <$> arbitraryHost
            , AltNameRFC822 . ("user@" ++) <$> arbitraryHost
            , AltNameURI . ("https://" ++) <$> arbitraryHost
            , AltNameIP . B.pack <$> (elements [4, 16] >>= vector)
            , AltNameDN <$> arbitrary
            , AltNameOther <$> arbitraryOID <*> der
            , AltNameX400 <$> der
            , AltNameEDIParty <$> der
            , AltNameRegisteredID <$> arbitraryOID
            ]
      where
        arbitraryHost = listOf1 (elements "abcxyz.-")
        der = (\n -> encodeASN1' DER [IntVal n]) <$> arbitrary
        arbitraryOID = do
            a <- choose (0, 2)
            b <- if a < 2 then choose (0, 39) else choose (0, 1000)
            (\xs -> a : b : xs) <$> listOf (getNonNegative <$> arbitrary)

instance Arbitrary GeneralSubtree where
    arbitrary =
        GeneralSubtree
            <$> (arbitrary >>= base)
            <*> pure 0
            <*> oneof [pure Nothing, Just <$> choose (0, 300)]
      where
        -- an address with a mask
        base (AltNameIP _) = AltNameIP . B.pack <$> (elements [8, 32] >>= vector)
        base a = return a

instance Arbitrary ExtNameConstraints where
    arbitrary = ExtNameConstraints <$> arbitrary <*> arbitrary

instance Arbitrary ExtSubjectAltName where
    arbitrary = ExtSubjectAltName <$> arbitrary

instance Arbitrary ExtAuthorityKeyId where
    arbitrary = do
        k <- oneof [pure Nothing, Just . B.pack <$> listOf1 arbitrary]
        is <- oneof [pure Nothing, curry Just <$> listOf1 arbitrary <*> arbitrary]
        return defaultExtAuthorityKeyId{akiKeyIdentifier = k, akiIssuerSerial = is}

instance Arbitrary DistributionPointName where
    arbitrary =
        oneof
            [ DistributionPointFullName <$> listOf1 arbitrary
            , DistributionPointRelativeName . concat . getRDNs
                <$> arbitrary `suchThat` (not . null . getRDNs)
            ]

instance Arbitrary DistributionPoint where
    arbitrary = do
        name <- oneof [pure Nothing, Just <$> arbitrary]
        rs <-
            oneof
                [ pure Nothing
                , Just . nub . sort <$> listOf1 (elements [Reason_Unused .. Reason_AACompromise])
                ]
        issuer <- case name of
            Nothing -> Just <$> listOf1 arbitrary
            Just _ -> oneof [pure Nothing, Just <$> listOf1 arbitrary]
        return
            defaultDistributionPoint{dpName = name, dpReasons = rs, dpCRLIssuer = issuer}

instance Arbitrary ExtCrlDistributionPoints where
    arbitrary = ExtCrlDistributionPoints <$> listOf1 arbitrary

-- NameConstraints with permitted dNSName "example.com" and
-- excluded iPAddress 10.0.0.0/8, as encoded by OpenSSL.
property_name_constraints_der :: Bool
property_name_constraints_der =
    extensionDecode raw
        == Just
            ( Right $
                ExtNameConstraints
                    [GeneralSubtree (AltNameDNS "example.com") 0 Nothing]
                    [GeneralSubtree (AltNameIP (B.pack [10, 0, 0, 0, 255, 0, 0, 0])) 0 Nothing]
            )
        && extensionEncode
            True
            (either error id (fromJust (extensionDecode raw)) :: ExtNameConstraints)
            == raw
  where
    raw = ExtensionRaw [2, 5, 29, 30] True der
    der =
        B.pack $
            [0x30, 0x1f, 0xa0, 0x0f, 0x30, 0x0d, 0x82, 0x0b]
                ++ map (fromIntegral . fromEnum) "example.com"
                ++ [0xa1, 0x0c, 0x30, 0x0a, 0x87, 0x08, 10, 0, 0, 0, 255, 0, 0, 0]

-- Unknown key usage bits and a bogus bit string length are ignored.
property_key_usage_unknown_bits :: Bool
property_key_usage_unknown_bits =
    extDecode [BitString (toBitArray (B.pack [0x80, 0x40]) 6)]
        == Right (ExtKeyUsage [KeyUsage_digitalSignature])
        && extDecode [BitString (toBitArray B.empty 7)] == Right (ExtKeyUsage [])

property_malformed_extensions :: Bool
property_malformed_extensions =
    isLeft
        ( extDecode [Start Sequence, IntVal 1, End Sequence]
            :: Either String ExtExtendedKeyUsage
        )
        && isLeft
            ( extDecode [Start Sequence, End Sequence]
                :: Either String ExtCrlDistributionPoints
            )
  where
    isLeft = either (const True) (const False)

-- Unsupported GeneralName types in a SAN are skipped, but not in constraints.
property_san_keeps_names :: Bool
property_san_keeps_names =
    extDecode san == Right (ExtSubjectAltName names)
        && extEncode (ExtSubjectAltName names) == san
        && extDecode nc
            == Right
                (ExtNameConstraints [GeneralSubtree (AltNameRegisteredID [1, 2, 3]) 0 Nothing] [])
  where
    san =
        [Start Sequence]
            ++ registeredID
            ++ [Other Context 2 (B.pack [0x61])]
            ++ otherName
            ++ [Start (Container Context 4)]
            ++ toASN1 dn [End (Container Context 4)]
            ++ [End Sequence]
    names =
        [ AltNameRegisteredID [1, 2, 3]
        , AltNameDNS "a"
        , AltNameOther [1, 2, 3] (encodeASN1' DER [IntVal 1])
        , AltNameDN dn
        ]
    nc =
        [Start Sequence, Start (Container Context 0), Start Sequence]
            ++ registeredID
            ++ [End Sequence, End (Container Context 0), End Sequence]
    dn = DistinguishedName [(getObjectID DnCommonName, asn1CharacterString UTF8 "x")]
    registeredID = [Other Context 8 (B.pack [0x2a, 0x03])]
    otherName =
        [ Start (Container Context 0)
        , OID [1, 2, 3]
        , Start (Container Context 0)
        , IntVal 1
        , End (Container Context 0)
        , End (Container Context 0)
        ]

-- A certificate whose validity cannot be decoded is rejected with 'Left'
-- rather than an exception thrown lazily from the decoder.
property_lazy_decode_error :: Bool
property_lazy_decode_error =
    case decodeSignedCertificate corrupted of
        Left e -> length e > 0
        Right _ -> False
  where
    t = timeConvert (Date 2020 January 1) :: DateTime
    dn = DistinguishedName [(getObjectID DnCommonName, asn1CharacterString UTF8 "x")]
    cert =
        Certificate
            2
            1
            (SignatureALG HashSHA256 PubKeyALG_RSA)
            dn
            (t, t)
            dn
            (PubKeyRSA (RSA.PublicKey 1 0x7f 3))
            (Extensions Nothing)
    encoded =
        encodeSignedObject $
            fst $
                objectToSignedExact
                    (\_ -> (B.pack [1], SignatureALG HashSHA256 PubKeyALG_RSA, ()))
                    cert
    -- replace the first character of the first UTCTime with a non-ASCII byte
    (before, rest) = B.breakSubstring (B.pack [0x17, 0x0d]) encoded
    corrupted = before <> B.pack [0x17, 0x0d, 0xff] <> B.drop 3 rest

-- | A certificate re-encoded after modifying its ASN.1 stream.
modifiedCertificate :: ([ASN1] -> [ASN1]) -> Either String SignedCertificate
modifiedCertificate f = decodeSignedCertificate $ encodeASN1' DER $ f asn1
  where
    t = timeConvert (Date 2020 January 1) :: DateTime
    dn = DistinguishedName [(getObjectID DnCommonName, asn1CharacterString UTF8 "x")]
    cert =
        Certificate
            2
            1
            (SignatureALG HashSHA256 PubKeyALG_RSA)
            dn
            (t, t)
            dn
            (PubKeyRSA (RSA.PublicKey 1 0x7f 3))
            (Extensions Nothing)
    encoded =
        encodeSignedObject $
            fst $
                objectToSignedExact
                    (\_ -> (B.pack [1], SignatureALG HashSHA256 PubKeyALG_RSA, ()))
                    cert
    asn1 = either (error . show) id $ decodeASN1' DER encoded

isLeft' :: Either a b -> Bool
isLeft' = either (const True) (const False)

property_signed_strict :: Bool
property_signed_strict =
    not (isLeft' (modifiedCertificate id))
        && isLeft' (modifiedCertificate (++ [IntVal 1]))
        && isLeft' (modifiedCertificate (\l -> init l ++ [IntVal 1, End Sequence]))
        && isLeft' (modifiedCertificate (\l -> Start Set : init (drop 1 l) ++ [End Set]))

property_duplicate_extensions :: Bool
property_duplicate_extensions =
    isLeft'
        ( fromASN1 (toASN1 (Extensions (Just [e, e])) [])
            :: Either String (Extensions, [ASN1])
        )
  where
    e = extensionEncode False (ExtKeyUsage [KeyUsage_digitalSignature])

-- Data after the RSA key in the BIT STRING must not be parsed as
-- following fields.
property_rsa_pubkey_trailing :: Bool
property_rsa_pubkey_trailing =
    not (isLeft' (decode key)) && isLeft' (decode (key ++ [IntVal 1]))
  where
    key = [Start Sequence, IntVal 0xc5, IntVal 3, End Sequence]
    decode k =
        fromASN1
            [ Start Sequence
            , Start Sequence
            , OID [1, 2, 840, 113549, 1, 1, 1]
            , Null
            , End Sequence
            , BitString (toBitArray (encodeASN1' DER k) 0)
            , End Sequence
            ]
            :: Either String (PubKey, [ASN1])

property_pss_hash :: Bool
property_pss_hash =
    decode (pss [2, 16, 840, 1, 101, 3, 4, 2, 1])
        == Right (SignatureALG HashSHA256 PubKeyALG_RSAPSS, [])
        -- sha256WithRSAEncryption is not a hash algorithm
        && isLeft' (decode (pss [1, 2, 840, 113549, 1, 1, 11]))
        -- a bare hash algorithm is not a signature algorithm
        && decode [Start Sequence, OID sha256, End Sequence]
            == Right (SignatureALG_Unknown sha256, [])
        && decode (toASN1 (SignatureALG HashSHA384 PubKeyALG_RSAPSS) [])
            == Right (SignatureALG HashSHA384 PubKeyALG_RSAPSS, [])
  where
    sha256 = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    decode l = fromASN1 l :: Either String (SignatureALG, [ASN1])
    pss h =
        [ Start Sequence
        , OID [1, 2, 840, 113549, 1, 1, 10]
        , Start Sequence
        , Start (Container Context 0)
        , Start Sequence
        , OID h
        , End Sequence
        , End (Container Context 0)
        , Start (Container Context 1)
        , Start Sequence
        , OID [1, 2, 840, 113549, 1, 1, 8]
        , Start Sequence
        , OID h
        , End Sequence
        , End Sequence
        , End (Container Context 1)
        , Start (Container Context 2)
        , IntVal 32
        , End (Container Context 2)
        , End Sequence
        , End Sequence
        ]

-- Malformed inner encodings of PKCS#8 keys return Left, not an exception.
property_privkey_malformed :: Bool
property_privkey_malformed =
    all
        isLeft'
        [ decode [1, 2, 840, 113549, 1, 1, 1] Null rsaInner
        , decode [1, 3, 101, 112] none edInner
        ]
  where
    rsaInner = B.pack [0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x00]
    edInner = B.pack [0x17, 0x01, 0xff]
    none = End Sequence
    decode oid param inner =
        fromASN1
            ( [Start Sequence, IntVal 0, Start Sequence, OID oid]
                ++ (if param == none then [] else [param])
                ++ [End Sequence, OctetString inner, End Sequence]
            )
            :: Either String (PrivKey, [ASN1])

sampleCert :: Certificate
sampleCert =
    Certificate
        2
        1
        (SignatureALG HashSHA256 PubKeyALG_RSA)
        dn
        (t, t)
        dn
        (PubKeyRSA (RSA.PublicKey 1 0x7f 3))
        (Extensions Nothing)
  where
    t = timeConvert (Date 2020 January 1) :: DateTime
    dn = DistinguishedName [(getObjectID DnCommonName, asn1CharacterString UTF8 "x")]

decodeCert :: [ASN1] -> Either String (Certificate, [ASN1])
decodeCert = fromASN1

property_key_usage_der :: Bool
property_key_usage_der =
    extEncodeBs (ExtKeyUsage [KeyUsage_digitalSignature]) == B.pack [3, 2, 7, 0x80]
        && extEncodeBs (ExtKeyUsage [KeyUsage_keyCertSign, KeyUsage_cRLSign])
            == B.pack [3, 2, 1, 0x06]
        && extEncodeBs (ExtKeyUsage [KeyUsage_digitalSignature, KeyUsage_decipherOnly])
            == B.pack [3, 3, 7, 0x80, 0x80]
        && extEncodeBs (ExtKeyUsage []) == B.pack [3, 1, 0]

property_basic_constraints_no_ca :: Bool
property_basic_constraints_no_ca =
    extDecode [Start Sequence, IntVal 0, End Sequence]
        == Right (ExtBasicConstraints False (Just 0))

property_aki_issuer_serial :: Bool
property_aki_issuer_serial =
    extDecode (aki [Other Context 0 kid] ++ issuer ++ serial ++ [End Sequence])
        == Right full
        && extDecode (aki issuer ++ serial ++ [End Sequence])
            == Right full{akiKeyIdentifier = Nothing}
        && isLeft'
            (extDecode (aki issuer ++ [End Sequence]) :: Either String ExtAuthorityKeyId)
        && case full of
            ExtAuthorityKeyId k -> k == kid
            _ -> False
  where
    kid = B.pack [1, 2, 3]
    dn = DistinguishedName [(getObjectID DnCommonName, asn1CharacterString UTF8 "x")]
    aki = (Start Sequence :)
    issuer =
        [Start (Container Context 1), Start (Container Context 4)]
            ++ toASN1 dn [End (Container Context 4), End (Container Context 1)]
    serial = [Other Context 2 (B.pack [0x80])]
    full =
        defaultExtAuthorityKeyId
            { akiKeyIdentifier = Just kid
            , akiIssuerSerial = Just ([AltNameDN dn], -128)
            }

-- Unknown keys are kept as PubKeyUnknown, with or without parameters.
property_unknown_pubkey :: Bool
property_unknown_pubkey =
    decode [] == Right (PubKeyUnknown oid key, [])
        && decode [Start Sequence, End Sequence] == Right (PubKeyUnknown oid key, [])
  where
    oid = [1, 2, 3, 4]
    key = B.pack [1, 2, 3]
    decode params =
        fromASN1
            ( [Start Sequence, Start Sequence, OID oid]
                ++ params
                ++ [End Sequence, BitString (toBitArray key 0), End Sequence]
            )
            :: Either String (PubKey, [ASN1])

property_ec_prime_roundtrip :: Bool
property_ec_prime_roundtrip = fromASN1 (toASN1 key []) == Right (key, [])
  where
    key =
        PubKeyEC
            PubKeyEC_Prime
                { pubkeyEC_pub = SerializedPoint (B.pack [4, 1, 2])
                , pubkeyEC_a = 3
                , pubkeyEC_b = 0x1234
                , pubkeyEC_prime = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
                , pubkeyEC_generator = SerializedPoint (B.pack [4, 5, 6])
                , pubkeyEC_order = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
                , pubkeyEC_cofactor = 1
                , pubkeyEC_seed = 0x3045ae6fc8422f64ed579528d38120eae12196d5
                }

property_unique_ids :: Bool
property_unique_ids =
    decodeCert (toASN1 sampleCert [] ++ [Other Context 1 b, Other Context 2 b])
        == Right (sampleCert, [])
        && isLeft' (decodeCert (toASN1 sampleCert{certVersion = 3} []))
  where
    b = B.pack [0, 1]

-- Times with a zone offset are converted to UTC, and UTCTime is used
-- from 1950 through 2049.
property_validity_time :: Bool
property_validity_time =
    fmap (certValidity . fst) (decodeCert (map withOffset (toASN1 sampleCert [])))
        == Right (t', t')
        && map timeType (validity 1949) == [TimeGeneralized]
        && map timeType (validity 1950) == [TimeUTC]
        && map timeType (validity 2049) == [TimeUTC]
        && map timeType (validity 2050) == [TimeGeneralized]
  where
    (t, _) = certValidity sampleCert
    t' = timeAdd t (Hours (-9))
    withOffset (ASN1Time ty d _) = ASN1Time ty d (Just (TimezoneOffset 540))
    withOffset a = a
    validity y =
        take
            1
            [ a
            | a@ASN1Time{} <-
                toASN1 sampleCert{certValidity = (year y, year y)} []
            ]
    year y = timeConvert (Date y January 1) :: DateTime
    timeType (ASN1Time ty _ _) = ty
    timeType _ = TimeUTC

property_crl_v1 :: Bool
property_crl_v1 =
    take 1 encoded /= [IntVal 0]
        && fromASN1 encoded == Right (crl, [])
  where
    t = timeConvert (Date 2020 January 1) :: DateTime
    crl =
        CRL
            0
            (SignatureALG HashSHA256 PubKeyALG_RSA)
            (DistinguishedName [(getObjectID DnCommonName, asn1CharacterString UTF8 "x")])
            t
            Nothing
            []
            (Extensions Nothing)
    encoded = toASN1 crl []

-- RFC 5915: the private key octet string is as long as the order.
property_ec_privkey_length :: Bool
property_ec_privkey_length =
    [B.length o | OctetString o <- asn1] == [32]
        && fromASN1 asn1 == Right (key, [])
  where
    key = PrivKeyEC (PrivKeyEC_Named ECC.SEC_p256r1 1)
    asn1 = toASN1 key []

-- Explicit parameters name a curve only if the generator and the
-- cofactor match too.
property_ec_curve_name :: Bool
property_ec_curve_name =
    ecPubKeyCurveName (explicit g 1) == Just ECC.SEC_p256r1
        && ecPubKeyCurveName (explicit (ECC.pointMul curve 2 g) 1) == Nothing
        && ecPubKeyCurveName (explicit g 2) == Nothing
  where
    curve = ECC.getCurveByName ECC.SEC_p256r1
    cc = ECC.common_curve curve
    p = case curve of
        ECC.CurveFP (ECC.CurvePrime q _) -> q
        _ -> 0
    g = ECC.ecc_g cc
    point (ECC.Point x y) = SerializedPoint (B.cons 4 (i2ospOf_ 32 x <> i2ospOf_ 32 y))
    point ECC.PointO = SerializedPoint (B.singleton 0)
    explicit gen h =
        PubKeyEC_Prime
            { pubkeyEC_pub = point g
            , pubkeyEC_a = ECC.ecc_a cc
            , pubkeyEC_b = ECC.ecc_b cc
            , pubkeyEC_prime = p
            , pubkeyEC_generator = point gen
            , pubkeyEC_order = ECC.ecc_n cc
            , pubkeyEC_cofactor = h
            , pubkeyEC_seed = 0
            }

property_pss_default :: Bool
property_pss_default =
    fromASN1 asn1 == Right (SignatureALG HashSHA1 PubKeyALG_RSAPSS, [])
        && toASN1 (SignatureALG HashSHA1 PubKeyALG_RSAPSS) [] == asn1
  where
    asn1 =
        [ Start Sequence
        , OID [1, 2, 840, 113549, 1, 1, 10]
        , Start Sequence
        , End Sequence
        , End Sequence
        ]

-- An X9.42 DH public key generated by OpenSSL is decoded and re-encoded
-- unchanged.
property_dh_pubkey :: Bool
property_dh_pubkey =
    case decodeASN1' DER der of
        Right asn1 -> case fromASN1 asn1 of
            Right (k@(PubKeyDH dh), []) ->
                pubkeyDH_q dh > 0
                    && pubkeyDH_y dh > 0
                    && encodeASN1' DER (toASN1 k []) == der
            _ -> False
        Left _ -> False
  where
    der =
        hexToBS $
            concat
                [ "3081f03081a806072a8648ce3e020130819c024100bb138b0c2555252ccb4b53"
                , "b674eea6ddcb7bbcbee1a52a4aef642d021df8e5bb86d5f16fd18a5510250aab"
                , "c740387fc57ceccebe9c4509e071e3c770478c052702405e0a4adbc2ed9dff00"
                , "ab23d851587759c7e27b539edbabc88be100b9c42b305434f1ddc8c445ce80d6"
                , "02e541f94bd221c36190b043966cf3c7a518c3760d7aa1021500ababf77df37b"
                , "481355fece9e7b5385348518c507034300024071e43594903589cf9cbc096df8"
                , "bfc7c0c6f3a92500d08f00299971fa9e83415e015ae3d8df3f5f553a90c4eeda"
                , "41085409b1ffe2b9b16ff75315870528996f0c"
                ]
    hexToBS (a : b : r) = read ("0x" ++ [a, b]) `B.cons` hexToBS r
    hexToBS _ = B.empty

-- An RSASSA-PSS key pair generated by OpenSSL (SHA-256, MGF1 SHA-256,
-- salt 32) is parsed and encoded back to the same DER.
property_rsapss_key :: Bool
property_rsapss_key =
    case (decode pubDER, decode privDER) of
        ( Right (pub@(PubKeyRSAPSS k (Just p)), [])
            , Right (priv@(PrivKeyRSAPSS sk (Just p')), [])
            ) ->
                p == defaultPSSParams HashSHA256
                    && p' == p
                    && RSA.private_pub sk == k
                    && encodeASN1' DER (toASN1 pub []) == pubDER
                    && encodeASN1' DER (toASN1 priv []) == privDER
        _ -> False
  where
    decode :: ASN1Object a => B.ByteString -> Either String (a, [ASN1])
    decode bs = either (Left . show) fromASN1 (decodeASN1' DER bs)
    alg =
        "304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a"
            ++ "06092a864886f70d010108300d06096086480165030402010500a203020120"
    n =
        "be657c50fe582caf8b9c48bddcf1478f5d885e335c2053d8afee4a90c01e435a8340dff2"
            ++ "5c862be573f60b9c99a53ef92010ae866bfb778c7257f18bf228746102"
    pubDER = hexToBS $ "308190" ++ alg ++ "034b003048024100" ++ n ++ "03010001"
    privDER =
        hexToBS $
            concat
                [ "3082018a020100"
                , alg
                , "048201403082013c020100024100"
                , n
                , "0301000102404b111a3d98ba4d0bfd6065f1ad9dd797f7c99f52629d4051abb3a8e4"
                , "7f4aaf44de480b85bcd4a73bdb09c4b6f503c6ccdaf4702b39cf0e541e5a02ab4ab3"
                , "4801022100f76d88ad3a9d0e1ed1070a99015221565288617fcec45328115ecd387b"
                , "3b44c1022100c4fe222364d78291e0558a071342768cae8c7b0a2433cd4dac8955e3"
                , "e98cf7a1022100d82fbe520d7a9891d8755c8f1f965146894a5c563da5503b1c2247"
                , "1168aafa81022100addce6607ab642c5614bdde0d4bcca48ec1d8cd2ac9513d4443d"
                , "8a12f7a4b541022100aa4977e25992e372f53318407d440e5cbb7b329c9a31bdd45a"
                , "049ef22eb8a0bf"
                ]
    hexToBS (a : b : r) = read ("0x" ++ [a, b]) `B.cons` hexToBS r
    hexToBS _ = B.empty

-- An ML-KEM-512 key pair written by OpenSSL is read in the both form,
-- the public key matches the private key, and both encode back the same.
property_mlkem_openssl :: Bool
property_mlkem_openssl =
    case (decode opensslMLKEM512Pub, decode opensslMLKEM512) of
        (Right (pub@(PubKeyMLKEM512 ek), []), Right (priv@(PrivKeyMLKEM512 k), [])) ->
            privkeyMLKEM_form k == MLKeyBoth
                && fmap (fst . throwCryptoError . MLKEM.keyPairFromSeed p) (privkeyMLKEM_seed k)
                    == Just ek
                && privkeyToAlg priv == PubKeyALG_MLKEM512
                && encodeASN1' DER (toASN1 pub []) == opensslMLKEM512Pub
                && encodeASN1' DER (toASN1 priv []) == opensslMLKEM512
        _ -> False
  where
    p = Proxy :: Proxy MLKEM.MLKEM512
    decode :: ASN1Object a => B.ByteString -> Either String (a, [ASN1])
    decode bs = either (Left . show) fromASN1 (decodeASN1' DER bs)

-- Multi-valued RDNs are kept and differ from separate RDNs; the canonical
-- form ignores the order inside an RDN.
property_multi_valued_rdn :: Bool
property_multi_valued_rdn =
    decode (encode multi) == Right (multi, [])
        && encodeASN1' DER (encode multi) /= encodeASN1' DER (encode single)
        && multi /= single
        && getDistinguishedElements multi == getDistinguishedElements single
        && single == fromRDNs [[cn], [o]]
        && canonicalDistinguishedName multi
            == canonicalDistinguishedName (fromRDNs [[o, cn]])
        && getDnElement DnOrganization multi == Just (snd o)
  where
    cn = (getObjectID DnCommonName, asn1CharacterString UTF8 "a")
    o = (getObjectID DnOrganization, asn1CharacterString UTF8 "o")
    multi = fromRDNs [[cn, o]]
    single = DistinguishedName [cn, o]
    encode dn = toASN1 dn []
    decode l = fromASN1 l :: Either String (DistinguishedName, [ASN1])

-- Every DnElement maps to a distinct OID and back.
property_dn_element_oid :: Bool
property_dn_element_oid =
    all (\e -> fromObjectID (getObjectID e) == Just e) els
        && length (nub (map getObjectID els)) == length els
  where
    els = [minBound .. maxBound] :: [DnElement]

-- Non-default PSS parameters are kept, explicit defaults are normalized,
-- and trailer fields other than 1 are rejected.
property_pss_params :: Bool
property_pss_params =
    decode (pssAsn1 [hash sha384 0, mgf sha256, salt 0])
        == Right (SignatureALG_RSAPSS custom, [])
        && toASN1 (SignatureALG_RSAPSS custom) []
            == pssAsn1 [hash sha384 0, mgf sha256, salt 0]
        && rsaPSSSignatureALG custom == SignatureALG_RSAPSS custom
        && signatureALGPSSParams (SignatureALG_RSAPSS custom) == Just custom
        && decode (pssAsn1 [hash sha1 0, mgf sha1, salt 20])
            == Right (SignatureALG HashSHA1 PubKeyALG_RSAPSS, [])
        && rsaPSSSignatureALG (defaultPSSParams HashSHA256)
            == SignatureALG HashSHA256 PubKeyALG_RSAPSS
        && decode (pssAsn1 [noNull (hash sha384 0), noNull (mgf sha256), salt 0])
            == Right (SignatureALG_RSAPSS custom, [])
        && isLeft'
            ( decode
                (pssAsn1 [[Start (Container Context 3), IntVal 2, End (Container Context 3)]])
            )
  where
    noNull = filter (/= Null)
    custom = (defaultPSSParams HashSHA384){pssMGFHash = HashSHA256, pssSaltLength = 0}
    sha1 = [1, 3, 14, 3, 2, 26]
    sha256 = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    sha384 = [2, 16, 840, 1, 101, 3, 4, 2, 2]
    decode l = fromASN1 l :: Either String (SignatureALG, [ASN1])
    ctx n l = Start (Container Context n) : l ++ [End (Container Context n)]
    hash h n = ctx n [Start Sequence, OID h, Null, End Sequence]
    mgf h =
        ctx
            1
            [ Start Sequence
            , OID [1, 2, 840, 113549, 1, 1, 8]
            , Start Sequence
            , OID h
            , Null
            , End Sequence
            , End Sequence
            ]
    salt n = ctx 2 [IntVal n]
    pssAsn1 fields =
        [Start Sequence, OID [1, 2, 840, 113549, 1, 1, 10], Start Sequence]
            ++ concat fields
            ++ [End Sequence, End Sequence]

-- The usual form (as written by OpenSSL), and points with reasons and a
-- cRLIssuer, or with a cRLIssuer only, are kept; a point with neither a
-- name nor a cRLIssuer is rejected.
property_crl_dp_der :: Bool
property_crl_dp_der =
    extensionDecode (ExtensionRaw [2, 5, 29, 31] False der) == Just (Right simple)
        && extEncodeBs simple == der
        && extDecode
            ( [Start Sequence]
                ++ dp (uriName ++ [Other Context 1 (B.pack [6, 0x40])] ++ issuer)
                ++ dp issuer
                ++ [End Sequence]
            )
            == Right
                ( ExtCrlDistributionPoints
                    [ uriDP
                        { dpReasons = Just [Reason_KeyCompromise]
                        , dpCRLIssuer = Just [AltNameDNS "a"]
                        }
                    , defaultDistributionPoint{dpCRLIssuer = Just [AltNameDNS "a"]}
                    ]
                )
        && isLeft'
            ( extDecode ([Start Sequence] ++ dp [] ++ [End Sequence])
                :: Either String ExtCrlDistributionPoints
            )
  where
    url = "http://crl.example.com/ca.crl"
    uriDP =
        defaultDistributionPoint
            { dpName = Just (DistributionPointFullName [AltNameURI url])
            }
    simple = ExtCrlDistributionPoints [uriDP]
    der =
        B.pack
            ( [0x30, 0x25, 0x30, 0x23, 0xa0, 0x21, 0xa0, 0x1f, 0x86, 0x1d]
                ++ map (fromIntegral . fromEnum) url
            )
    uriName =
        [ Start (Container Context 0)
        , Start (Container Context 0)
        , Other Context 6 (B.pack (map (fromIntegral . fromEnum) url))
        , End (Container Context 0)
        , End (Container Context 0)
        ]
    issuer =
        [ Start (Container Context 2)
        , Other Context 2 (B.pack [0x61])
        , End (Container Context 2)
        ]
    dp xs = [Start Sequence] ++ xs ++ [End Sequence]

property_extension_id :: (Show e, Eq e, Extension e) => e -> Bool
property_extension_id e = case extDecode (extEncode e) of
    Left err -> error err
    Right v
        | v == e -> True
        | otherwise -> error ("expected " ++ show e ++ " got: " ++ show v)

-- Per-family AlgorithmIdentifier parameters contract:
-- ECDSA (RFC 5758 3.2, RFC 3279 2.2.3) and DSA (RFC 5758 3.1, RFC 3279
-- 2.2.2) omit the parameters field; RSA PKCS#1 v1.5 encodes an ASN.1
-- NULL (RFC 3279 2.2.1, RFC 9688 3.1 for SHA-3); EdDSA omits the field
-- (RFC 8410 3).
property_sig_alg_parameters :: SignatureALG -> Bool
property_sig_alg_parameters alg@(SignatureALG _ pub)
    | pub == PubKeyALG_EC || pub == PubKeyALG_DSA = Null `notElem` toASN1 alg []
    | pub == PubKeyALG_RSA = Null `elem` toASN1 alg []
property_sig_alg_parameters alg@(SignatureALG_IntrinsicHash _) =
    Null `notElem` toASN1 alg []
property_sig_alg_parameters _ = True

main =
    defaultMain $
        testGroup
            "X509"
            [ testGroup
                "marshall"
                [ testProperty "pubkey" (property_unmarshall_marshall_id :: PubKey -> Bool)
                , testProperty "privkey" (property_unmarshall_marshall_id :: PrivKey -> Bool)
                , testProperty
                    "signature alg"
                    (property_unmarshall_marshall_id :: SignatureALG -> Bool)
                , testGroup
                    "extension"
                    [ testProperty "key-usage" (property_extension_id :: ExtKeyUsage -> Bool)
                    , testProperty
                        "extended-key-usage"
                        (property_extension_id :: ExtExtendedKeyUsage -> Bool)
                    , testProperty
                        "subject-alt-name"
                        (property_extension_id :: ExtSubjectAltName -> Bool)
                    , testProperty
                        "authority-key-id"
                        (property_extension_id :: ExtAuthorityKeyId -> Bool)
                    , testProperty
                        "crl-distribution-points"
                        (property_extension_id :: ExtCrlDistributionPoints -> Bool)
                    , testProperty "crl-distribution-points-der" property_crl_dp_der
                    , testProperty
                        "name-constraints"
                        (property_extension_id :: ExtNameConstraints -> Bool)
                    , testProperty "name-constraints DER" property_name_constraints_der
                    ]
                , testGroup
                    "malformed"
                    [ testProperty "key-usage unknown bits" property_key_usage_unknown_bits
                    , testProperty "extensions" property_malformed_extensions
                    , testProperty "SAN keeps all name forms" property_san_keeps_names
                    , testProperty "lazy decode error" property_lazy_decode_error
                    , testProperty "signed object" property_signed_strict
                    , testProperty "duplicate extensions" property_duplicate_extensions
                    , testProperty "RSA key trailing data" property_rsa_pubkey_trailing
                    , testProperty "PSS hash" property_pss_hash
                    , testProperty "private key" property_privkey_malformed
                    ]
                , testGroup
                    "interoperability"
                    [ testProperty "KeyUsage DER" property_key_usage_der
                    , testProperty "BasicConstraints without cA" property_basic_constraints_no_ca
                    , testProperty "AKI with issuer and serial" property_aki_issuer_serial
                    , testProperty "unknown public key" property_unknown_pubkey
                    , testProperty "EC explicit parameters" property_ec_prime_roundtrip
                    , testProperty "unique IDs" property_unique_ids
                    , testProperty "validity time" property_validity_time
                    , testProperty "v1 CRL" property_crl_v1
                    , testProperty "PSS default parameters" property_pss_default
                    , testProperty "PSS parameters" property_pss_params
                    , testProperty "multi-valued RDN" property_multi_valued_rdn
                    , testProperty "DN element OID" property_dn_element_oid
                    , testProperty "DH public key" property_dh_pubkey
                    , testProperty "RSASSA-PSS key" property_rsapss_key
                    , testProperty "ML-KEM OpenSSL key" property_mlkem_openssl
                    , testProperty "EC private key length" property_ec_privkey_length
                    , testProperty "EC curve name" property_ec_curve_name
                    ]
                , testGroup
                    "signature-alg-parameters"
                    [ testProperty
                        "per-family"
                        property_sig_alg_parameters
                    ]
                , testProperty
                    "extensions"
                    (property_unmarshall_marshall_id :: Extensions -> Bool)
                , testProperty
                    "certificate"
                    (property_unmarshall_marshall_id :: Certificate -> Bool)
                , testProperty "crl" (property_unmarshall_marshall_id :: CRL -> Bool)
                ]
            , testGroup
                "show"
                [testProperty "ec privkey is redacted" property_ec_show_redacts]
            , testGroup
                "ML-DSA private key"
                [ testProperty "seed, expandedKey and both" property_mldsa_forms
                , testProperty
                    "each form is written back as itself"
                    property_mldsa_form_round_trip
                , testProperty
                    "a generated seed survives the round trip"
                    property_mldsa_generated_seed
                , testProperty
                    "a key OpenSSL wrote reads and writes back unchanged"
                    (property_mldsa_openssl)
                , testProperty "both refused if they disagree" property_mldsa_mismatch
                , testProperty "is redacted" property_mldsa_show_redacts
                ]
            ]
