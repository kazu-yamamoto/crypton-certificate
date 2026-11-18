{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Test.Tasty
import Test.Tasty.QuickCheck

import qualified Data.ByteString as B

import Control.Monad

import Crypto.Debug (DebugShow (..))
import Crypto.Error (throwCryptoError)
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.MLDSA as MLDSA
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

import MLDSAKeys

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
            , PubKeyDSA <$> arbitrary
            , -- , PubKeyECDSA ECDSA_Hash_SHA384 <$> (B.pack <$> replicateM 384 arbitrary)
              PubKeyX25519 <$> arbitrary
            , PubKeyX448 <$> arbitrary
            , PubKeyEd25519 <$> arbitrary
            , PubKeyEd448 <$> arbitrary
            , PubKeyMLDSA44 . MLDSA.toPublic <$> arbitraryMLDSA (Proxy :: Proxy MLDSA.MLDSA44)
            , PubKeyMLDSA65 . MLDSA.toPublic <$> arbitraryMLDSA (Proxy :: Proxy MLDSA.MLDSA65)
            , PubKeyMLDSA87 . MLDSA.toPublic <$> arbitraryMLDSA (Proxy :: Proxy MLDSA.MLDSA87)
            ]

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
            , PrivKeyDSA <$> arbitrary
            , -- , PrivKeyECDSA ECDSA_Hash_SHA384 <$> (B.pack <$> replicateM 384 arbitrary)
              PrivKeyX25519 <$> arbitrary
            , PrivKeyX448 <$> arbitrary
            , PrivKeyEd25519 <$> arbitrary
            , PrivKeyEd448 <$> arbitrary
            , PrivKeyMLDSA44 <$> arbitraryPrivMLDSA (Proxy :: Proxy MLDSA.MLDSA44)
            , PrivKeyMLDSA65 <$> arbitraryPrivMLDSA (Proxy :: Proxy MLDSA.MLDSA65)
            , PrivKeyMLDSA87 <$> arbitraryPrivMLDSA (Proxy :: Proxy MLDSA.MLDSA87)
            ]

arbitraryMLDSA :: MLDSA.MLDSA p => proxy p -> Gen (MLDSA.SigningKey p)
arbitraryMLDSA p = snd . throwCryptoError . MLDSA.keyPairFromSeed p <$> arbitraryBS 32 32

-- | All three forms are generated, so that the marshalling round trip
-- covers each of them and not just whichever one this module would pick.
arbitraryPrivMLDSA :: MLDSA.MLDSA p => proxy p -> Gen (PrivKeyMLDSA p)
arbitraryPrivMLDSA p = do
    form <- elements [MLDSAKeySeed, MLDSAKeyExpanded, MLDSAKeyBoth]
    throwCryptoError . privkeyMLDSAFromSeed p form <$> arbitraryBS 32 32

instance Arbitrary HashALG where
    arbitrary =
        elements
            [HashMD2, HashMD5, HashSHA1, HashSHA224, HashSHA256, HashSHA384, HashSHA512]

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
mldsaForms :: B.ByteString -> [(MLDSAKeyForm, [ASN1])]
mldsaForms seed =
    [ (MLDSAKeySeed, [Other Context 0 seed])
    , (MLDSAKeyExpanded, [OctetString expanded])
    ,
        ( MLDSAKeyBoth
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
    let k = throwCryptoError $ privkeyMLDSAFromSeed p MLDSAKeySeed seed
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
                formOf k == Just MLDSAKeyBoth
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
                && (form == MLDSAKeyExpanded || hex seed `isInfixOf` debugged)

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
            ]
      where
        arbitraryHost = listOf1 (elements "abcxyz.-")

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
property_san_skips_unknown :: Bool
property_san_skips_unknown =
    extDecode
        ( [Start Sequence]
            ++ registeredID
            ++ [Other Context 2 (B.pack [0x61])]
            ++ otherName
            ++ [Start (Container Context 4)]
            ++ toASN1 dn [End (Container Context 4)]
            ++ [End Sequence]
        )
        == Right (ExtSubjectAltName [AltNameDNS "a", AltNameDN dn])
        && isLeft
            ( extDecode
                ( [Start Sequence, Start (Container Context 0), Start Sequence]
                    ++ registeredID
                    ++ [End Sequence, End (Container Context 0), End Sequence]
                )
                :: Either String ExtNameConstraints
            )
  where
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
    isLeft = either (const True) (const False)

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
    extDecode
        ( [Start Sequence, Other Context 0 kid, Start (Container Context 1)]
            ++ [Start (Container Context 4)]
            ++ toASN1
                (DistinguishedName [(getObjectID DnCommonName, asn1CharacterString UTF8 "x")])
                []
            ++ [End (Container Context 4), End (Container Context 1)]
            ++ [Other Context 2 (B.pack [1]), End Sequence]
        )
        == Right (ExtAuthorityKeyId kid)
  where
    kid = B.pack [1, 2, 3]

-- RSASSA-PSS keys (with parameters) and other unknown keys are kept as
-- PubKeyUnknown.
property_unknown_pubkey :: Bool
property_unknown_pubkey =
    decode [] == Right (PubKeyUnknown pss key, [])
        && decode [Start Sequence, End Sequence] == Right (PubKeyUnknown pss key, [])
  where
    pss = [1, 2, 840, 113549, 1, 1, 10]
    key = B.pack [1, 2, 3]
    decode params =
        fromASN1
            ( [Start Sequence, Start Sequence, OID pss]
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

property_extension_id :: (Show e, Eq e, Extension e) => e -> Bool
property_extension_id e = case extDecode (extEncode e) of
    Left err -> error err
    Right v
        | v == e -> True
        | otherwise -> error ("expected " ++ show e ++ " got: " ++ show v)

-- Per-family AlgorithmIdentifier parameters contract:
-- ECDSA (RFC 5758 3.2, RFC 3279 2.2.3) and DSA (RFC 5758 3.1, RFC 3279
-- 2.2.2) omit the parameters field; RSA PKCS#1 v1.5 encodes an ASN.1
-- NULL (RFC 3279 2.2.1); EdDSA omits the field (RFC 8410 3).
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
                        "name-constraints"
                        (property_extension_id :: ExtNameConstraints -> Bool)
                    , testProperty "name-constraints DER" property_name_constraints_der
                    ]
                , testGroup
                    "malformed"
                    [ testProperty "key-usage unknown bits" property_key_usage_unknown_bits
                    , testProperty "extensions" property_malformed_extensions
                    , testProperty "SAN skips unknown names" property_san_skips_unknown
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
