-- |
-- Module      : Data.X509.AlgorithmIdentifier
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
module Data.X509.AlgorithmIdentifier (
    HashALG (..),
    PubKeyALG (..),
    SignatureALG (..),
    PSSParams,
    pssHash,
    pssMGFHash,
    pssSaltLength,
    defaultPSSParams,
    rsaPSSSignatureALG,
    signatureALGPSSParams,

    -- * Internal
    pssKeyParamsFromASN1,
    pssKeyAlgToASN1,
) where

import Data.ASN1.Types
import Data.List (find)

-- | Hash Algorithm
data HashALG
    = HashMD2
    | HashMD5
    | HashSHA1
    | HashSHA224
    | HashSHA256
    | HashSHA384
    | HashSHA512
    | HashSHA3_224
    | HashSHA3_256
    | HashSHA3_384
    | HashSHA3_512
    deriving (Show, Eq)

-- | Public Key Algorithm
data PubKeyALG
    = -- | RSA Public Key algorithm
      PubKeyALG_RSA
    | -- | RSA PSS Key algorithm (RFC 3447)
      PubKeyALG_RSAPSS
    | -- | DSA Public Key algorithm
      PubKeyALG_DSA
    | -- | ECDSA & ECDH Public Key algorithm
      PubKeyALG_EC
    | -- | ECDH 25519 key agreement
      PubKeyALG_X25519
    | -- | ECDH 448 key agreement
      PubKeyALG_X448
    | -- | EdDSA 25519 signature algorithm
      PubKeyALG_Ed25519
    | -- | EdDSA 448 signature algorithm
      PubKeyALG_Ed448
    | -- | ML-DSA-44 signature algorithm (RFC 9881)
      PubKeyALG_MLDSA44
    | -- | ML-DSA-65 signature algorithm (RFC 9881)
      PubKeyALG_MLDSA65
    | -- | ML-DSA-87 signature algorithm (RFC 9881)
      PubKeyALG_MLDSA87
    | -- | ML-KEM-512 key encapsulation (RFC 9935)
      PubKeyALG_MLKEM512
    | -- | ML-KEM-768 key encapsulation (RFC 9935)
      PubKeyALG_MLKEM768
    | -- | ML-KEM-1024 key encapsulation (RFC 9935)
      PubKeyALG_MLKEM1024
    | -- | Diffie Hellman Public Key algorithm
      PubKeyALG_DH
    | -- | Unknown Public Key algorithm
      PubKeyALG_Unknown OID
    deriving (Show, Eq)

-- | Signature Algorithm, often composed of a public key algorithm and a hash
-- algorithm.  For some signature algorithms the hash algorithm is intrinsic to
-- the public key algorithm and is not needed in the data type.
data SignatureALG
    = SignatureALG HashALG PubKeyALG
    | SignatureALG_IntrinsicHash PubKeyALG
    | SignatureALG_Unknown OID
    | -- | RSASSA-PSS with parameters other than 'defaultPSSParams'.  With the
      -- default parameters, @SignatureALG h PubKeyALG_RSAPSS@ is used instead;
      -- 'rsaPSSSignatureALG' picks the right form.
      SignatureALG_RSAPSS PSSParams
    deriving (Show, Eq)

-- | RSASSA-PSS parameters (RFC 4055).  Only MGF1 and the trailer field 1
-- are supported.  The constructor is hidden; use 'defaultPSSParams' and
-- record update syntax.
data PSSParams = PSSParams
    { pssHash :: HashALG
    -- ^ The message hash
    , pssMGFHash :: HashALG
    -- ^ The hash used by MGF1
    , pssSaltLength :: Int
    -- ^ The salt length in bytes
    }
    deriving (Show, Eq)

-- | The hash for both the message and MGF1, and the salt length equal to
-- the hash length.
defaultPSSParams :: HashALG -> PSSParams
defaultPSSParams h = PSSParams h h (hashLength h)

hashLength :: HashALG -> Int
hashLength HashMD2 = 16
hashLength HashMD5 = 16
hashLength HashSHA1 = 20
hashLength HashSHA224 = 28
hashLength HashSHA256 = 32
hashLength HashSHA384 = 48
hashLength HashSHA512 = 64
hashLength HashSHA3_224 = 28
hashLength HashSHA3_256 = 32
hashLength HashSHA3_384 = 48
hashLength HashSHA3_512 = 64

-- | The RSASSA-PSS signature algorithm with the given parameters.
rsaPSSSignatureALG :: PSSParams -> SignatureALG
rsaPSSSignatureALG p
    | p == defaultPSSParams h = SignatureALG h PubKeyALG_RSAPSS
    | otherwise = SignatureALG_RSAPSS p
  where
    h = pssHash p

-- | The RSASSA-PSS parameters of a signature algorithm, if any.
signatureALGPSSParams :: SignatureALG -> Maybe PSSParams
signatureALGPSSParams (SignatureALG h PubKeyALG_RSAPSS) = Just (defaultPSSParams h)
signatureALGPSSParams (SignatureALG_RSAPSS p) = Just p
signatureALGPSSParams _ = Nothing

instance OIDable PubKeyALG where
    getObjectID PubKeyALG_RSA = [1, 2, 840, 113549, 1, 1, 1]
    getObjectID PubKeyALG_RSAPSS = [1, 2, 840, 113549, 1, 1, 10]
    getObjectID PubKeyALG_DSA = [1, 2, 840, 10040, 4, 1]
    getObjectID PubKeyALG_EC = [1, 2, 840, 10045, 2, 1]
    getObjectID PubKeyALG_X25519 = [1, 3, 101, 110]
    getObjectID PubKeyALG_X448 = [1, 3, 101, 111]
    getObjectID PubKeyALG_Ed25519 = [1, 3, 101, 112]
    getObjectID PubKeyALG_Ed448 = [1, 3, 101, 113]
    getObjectID PubKeyALG_MLDSA44 = [2, 16, 840, 1, 101, 3, 4, 3, 17]
    getObjectID PubKeyALG_MLDSA65 = [2, 16, 840, 1, 101, 3, 4, 3, 18]
    getObjectID PubKeyALG_MLDSA87 = [2, 16, 840, 1, 101, 3, 4, 3, 19]
    getObjectID PubKeyALG_MLKEM512 = [2, 16, 840, 1, 101, 3, 4, 4, 1]
    getObjectID PubKeyALG_MLKEM768 = [2, 16, 840, 1, 101, 3, 4, 4, 2]
    getObjectID PubKeyALG_MLKEM1024 = [2, 16, 840, 1, 101, 3, 4, 4, 3]
    getObjectID PubKeyALG_DH = [1, 2, 840, 10046, 2, 1]
    getObjectID (PubKeyALG_Unknown oid) = oid

sig_table :: [(OID, SignatureALG)]
sig_table =
    [ ([1, 2, 840, 113549, 1, 1, 5], SignatureALG HashSHA1 PubKeyALG_RSA)
    , ([1, 2, 840, 113549, 1, 1, 4], SignatureALG HashMD5 PubKeyALG_RSA)
    , ([1, 2, 840, 113549, 1, 1, 2], SignatureALG HashMD2 PubKeyALG_RSA)
    , ([1, 2, 840, 113549, 1, 1, 11], SignatureALG HashSHA256 PubKeyALG_RSA)
    , ([1, 2, 840, 113549, 1, 1, 12], SignatureALG HashSHA384 PubKeyALG_RSA)
    , ([1, 2, 840, 113549, 1, 1, 13], SignatureALG HashSHA512 PubKeyALG_RSA)
    , ([1, 2, 840, 113549, 1, 1, 14], SignatureALG HashSHA224 PubKeyALG_RSA)
    , ([1, 2, 840, 10040, 4, 3], SignatureALG HashSHA1 PubKeyALG_DSA)
    , ([1, 2, 840, 10045, 4, 1], SignatureALG HashSHA1 PubKeyALG_EC)
    , ([1, 2, 840, 10045, 4, 3, 1], SignatureALG HashSHA224 PubKeyALG_EC)
    , ([1, 2, 840, 10045, 4, 3, 2], SignatureALG HashSHA256 PubKeyALG_EC)
    , ([1, 2, 840, 10045, 4, 3, 3], SignatureALG HashSHA384 PubKeyALG_EC)
    , ([1, 2, 840, 10045, 4, 3, 4], SignatureALG HashSHA512 PubKeyALG_EC)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 1], SignatureALG HashSHA224 PubKeyALG_DSA)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 2], SignatureALG HashSHA256 PubKeyALG_DSA)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 5], SignatureALG HashSHA3_224 PubKeyALG_DSA)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 6], SignatureALG HashSHA3_256 PubKeyALG_DSA)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 7], SignatureALG HashSHA3_384 PubKeyALG_DSA)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 8], SignatureALG HashSHA3_512 PubKeyALG_DSA)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 9], SignatureALG HashSHA3_224 PubKeyALG_EC)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 10], SignatureALG HashSHA3_256 PubKeyALG_EC)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 11], SignatureALG HashSHA3_384 PubKeyALG_EC)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 12], SignatureALG HashSHA3_512 PubKeyALG_EC)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 13], SignatureALG HashSHA3_224 PubKeyALG_RSA)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 14], SignatureALG HashSHA3_256 PubKeyALG_RSA)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 15], SignatureALG HashSHA3_384 PubKeyALG_RSA)
    , ([2, 16, 840, 1, 101, 3, 4, 3, 16], SignatureALG HashSHA3_512 PubKeyALG_RSA)
    , ([1, 3, 101, 112], SignatureALG_IntrinsicHash PubKeyALG_Ed25519)
    , ([1, 3, 101, 113], SignatureALG_IntrinsicHash PubKeyALG_Ed448)
    ,
        ( [2, 16, 840, 1, 101, 3, 4, 3, 17]
        , SignatureALG_IntrinsicHash PubKeyALG_MLDSA44
        )
    ,
        ( [2, 16, 840, 1, 101, 3, 4, 3, 18]
        , SignatureALG_IntrinsicHash PubKeyALG_MLDSA65
        )
    ,
        ( [2, 16, 840, 1, 101, 3, 4, 3, 19]
        , SignatureALG_IntrinsicHash PubKeyALG_MLDSA87
        )
    ]

-- | Hash algorithms in RSASSA-PSS parameters.
pssHashTable :: [(OID, HashALG)]
pssHashTable =
    [ ([1, 3, 14, 3, 2, 26], HashSHA1)
    , ([2, 16, 840, 1, 101, 3, 4, 2, 1], HashSHA256)
    , ([2, 16, 840, 1, 101, 3, 4, 2, 2], HashSHA384)
    , ([2, 16, 840, 1, 101, 3, 4, 2, 3], HashSHA512)
    , ([2, 16, 840, 1, 101, 3, 4, 2, 4], HashSHA224)
    , ([2, 16, 840, 1, 101, 3, 4, 2, 7], HashSHA3_224)
    , ([2, 16, 840, 1, 101, 3, 4, 2, 8], HashSHA3_256)
    , ([2, 16, 840, 1, 101, 3, 4, 2, 9], HashSHA3_384)
    , ([2, 16, 840, 1, 101, 3, 4, 2, 10], HashSHA3_512)
    ]

pssHashOID :: HashALG -> OID
pssHashOID h =
    maybe (error ("unknown PSS hash " ++ show h)) fst $
        find ((==) h . snd) pssHashTable

oidSig :: OID -> SignatureALG
oidSig oid = maybe (SignatureALG_Unknown oid) id $ lookup oid sig_table

sigOID :: SignatureALG -> OID
sigOID (SignatureALG_Unknown oid) = oid
sigOID sig =
    maybe (error ("unknown OID for " ++ show sig)) fst $
        find ((==) sig . snd) sig_table

oidRSAPSS, oidMGF1 :: OID
oidRSAPSS = [1, 2, 840, 113549, 1, 1, 10]
oidMGF1 = [1, 2, 840, 113549, 1, 1, 8]

-- | Parse the contents of RSASSA-PSS-params, after its 'Start' 'Sequence'.
parsePSSParams :: [ASN1] -> Either String (PSSParams, [ASN1])
parsePSSParams xs0 = do
    (h, xs1) <- field 0 hashAlg HashSHA1 xs0
    (m, xs2) <- field 1 mgf HashSHA1 xs1
    (s, xs3) <- field 2 int 20 xs2
    (t, xs4) <- field 3 int 1 xs3
    case xs4 of
        End Sequence : rest
            | t == (1 :: Int) -> Right (PSSParams h m s, rest)
        _ -> Left "fromASN1: X509.SignatureALG: invalid PSS parameters"
  where
    field n p _ (Start (Container Context n') : xs)
        | n == n' = do
            (v, ys) <- p xs
            case ys of
                End (Container Context n'') : zs | n'' == n -> Right (v, zs)
                _ -> Left "fromASN1: X509.SignatureALG: invalid PSS parameters"
    field _ _ def xs = Right (def, xs)
    hashAlg (Start Sequence : OID o : Null : End Sequence : xs) = hashOID o xs
    hashAlg (Start Sequence : OID o : End Sequence : xs) = hashOID o xs
    hashAlg _ = Left "fromASN1: X509.SignatureALG: invalid PSS hash"
    hashOID o xs = case lookup o pssHashTable of
        Just h -> Right (h, xs)
        Nothing -> Left ("fromASN1: X509.SignatureALG: unknown PSS hash " ++ show o)
    mgf (Start Sequence : OID o : xs)
        | o == oidMGF1 = do
            (h, ys) <- hashAlg xs
            case ys of
                End Sequence : zs -> Right (h, zs)
                _ -> Left "fromASN1: X509.SignatureALG: invalid MGF1"
    mgf _ = Left "fromASN1: X509.SignatureALG: unsupported mask generation function"
    int (IntVal i : xs)
        | i >= 0 && i <= 65536 = Right (fromIntegral i, xs)
    int _ = Left "fromASN1: X509.SignatureALG: invalid PSS integer"

-- | Encode an AlgorithmIdentifier of RSASSA-PSS with its parameters,
-- omitting the DER default values.  Hash identifiers have NULL
-- parameters as in RFC 4055 2.1.
encodePSSParams :: PSSParams -> [ASN1] -> [ASN1]
encodePSSParams p xs =
    Start Sequence : OID oidRSAPSS : pssParamsToASN1 p (End Sequence : xs)

pssParamsToASN1 :: PSSParams -> [ASN1] -> [ASN1]
pssParamsToASN1 (PSSParams h m s) xs =
    Start Sequence : (hashField ++ mgfField ++ saltField ++ End Sequence : xs)
  where
    hashField
        | h == HashSHA1 = []
        | otherwise = ctx 0 [Start Sequence, OID (pssHashOID h), Null, End Sequence]
    mgfField
        | m == HashSHA1 = []
        | otherwise =
            ctx 1 $
                [Start Sequence, OID oidMGF1, Start Sequence, OID (pssHashOID m), Null]
                    ++ [End Sequence, End Sequence]
    saltField
        | s == 20 = []
        | otherwise = ctx 2 [IntVal (fromIntegral s)]
    ctx n l = Start (Container Context n) : l ++ [End (Container Context n)]

-- | Parse the rest of an RSASSA-PSS key AlgorithmIdentifier, after its
-- OID, up to and including its 'End' 'Sequence'.  Absent parameters
-- (RFC 4055 1.2) mean that the key is not restricted.
pssKeyParamsFromASN1 :: [ASN1] -> Either String (Maybe PSSParams, [ASN1])
pssKeyParamsFromASN1 (End Sequence : xs) = Right (Nothing, xs)
pssKeyParamsFromASN1 (Null : End Sequence : xs) = Right (Nothing, xs)
pssKeyParamsFromASN1 (Start Sequence : xs) = do
    (p, ys) <- parsePSSParams xs
    case ys of
        End Sequence : zs -> Right (Just p, zs)
        _ -> Left "fromASN1: RSASSA-PSS key: invalid parameters"
pssKeyParamsFromASN1 _ = Left "fromASN1: RSASSA-PSS key: invalid parameters"

-- | Encode an AlgorithmIdentifier of an RSASSA-PSS key.
pssKeyAlgToASN1 :: Maybe PSSParams -> [ASN1] -> [ASN1]
pssKeyAlgToASN1 mp xs =
    Start Sequence : OID oidRSAPSS : maybe id pssParamsToASN1 mp (End Sequence : xs)

instance ASN1Object SignatureALG where
    fromASN1 (Start Sequence : OID oid : Null : End Sequence : xs) =
        case oidSig oid of
            SignatureALG_IntrinsicHash _ ->
                Left "fromASN1: X509.SignatureALG: EdDSA and ML-DSA require absent parameter"
            signatureAlg -> Right (signatureAlg, xs)
    fromASN1 (Start Sequence : OID oid : End Sequence : xs) =
        Right (oidSig oid, xs)
    fromASN1 (Start Sequence : OID oid : Start Sequence : xs)
        | oid == oidRSAPSS = do
            (p, ys) <- parsePSSParams xs
            case ys of
                End Sequence : zs -> Right (rsaPSSSignatureALG p, zs)
                _ -> Left "fromASN1: X509.SignatureALG: invalid PSS parameters"
    fromASN1 _ =
        Left "fromASN1: X509.SignatureALG: unknown format"
    toASN1 (SignatureALG_Unknown oid) = \xs -> Start Sequence : OID oid : Null : End Sequence : xs
    toASN1 (SignatureALG h PubKeyALG_RSAPSS) = encodePSSParams (defaultPSSParams h)
    toASN1 (SignatureALG_RSAPSS p) = encodePSSParams p
    toASN1 signatureAlg@(SignatureALG_IntrinsicHash _) = \xs -> Start Sequence : OID (sigOID signatureAlg) : End Sequence : xs
    -- ECDSA: "the encoding MUST omit the parameters field"
    -- (RFC 5758 3.2, RFC 3279 2.2.3)
    toASN1 signatureAlg@(SignatureALG _ PubKeyALG_EC) = \xs -> Start Sequence : OID (sigOID signatureAlg) : End Sequence : xs
    -- DSA: "the encoding SHALL omit the parameters field"
    -- (RFC 5758 3.1, RFC 3279 2.2.2)
    toASN1 signatureAlg@(SignatureALG _ PubKeyALG_DSA) = \xs -> Start Sequence : OID (sigOID signatureAlg) : End Sequence : xs
    toASN1 signatureAlg = \xs -> Start Sequence : OID (sigOID signatureAlg) : Null : End Sequence : xs
