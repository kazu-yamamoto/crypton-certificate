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
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.Types
import Data.ByteArray (convert)
import Data.List (isInfixOf, nub, sort)
import Data.Proxy (Proxy (..))
import Data.X509

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
                    <$> ( listOf1 $
                            oneof
                                [ extensionEncode <$> arbitrary <*> (arbitrary :: Gen ExtKeyUsage)
                                ]
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
    map (fmap fst . mldsaPKCS8 . snd) (mldsaForms seed) == map (Right . expected) forms
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

property_extension_id :: (Show e, Eq e, Extension e) => e -> Bool
property_extension_id e = case extDecode (extEncode e) of
    Left err -> error err
    Right v
        | v == e -> True
        | otherwise -> error ("expected " ++ show e ++ " got: " ++ show v)

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
                , testProperty "both refused if they disagree" property_mldsa_mismatch
                , testProperty "is redacted" property_mldsa_show_redacts
                ]
            ]
