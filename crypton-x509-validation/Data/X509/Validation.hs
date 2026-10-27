{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module      : Data.X509.Validation
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Certificate checks and validations routines
--
-- Follows RFC5280 / RFC6818
module Data.X509.Validation (
    module Data.X509.Validation.Types,
    Fingerprint (..),

    -- * Failed validation types
    FailedReason (..),
    SignatureFailure (..),

    -- * Validation configuration types
    ValidationChecks (..),
    ValidationHooks (..),
    defaultChecks,
    defaultHooks,

    -- * Validation
    validate,
    validatePure,
    validateDefault,
    getFingerprint,

    -- * Cache
    module Data.X509.Validation.Cache,

    -- * Signature verification
    module Data.X509.Validation.Signature,
) where

import Control.Monad (when)
import Data.ASN1.Types
import Data.Bits
import Data.ByteString (ByteString, unpack)
import qualified Data.ByteString as B
import Data.Char (toLower)
import Data.Default
import Data.Hourglass
import Data.IP (IPv4, IPv6, fromIPv4, fromIPv6b, toIPv4, toIPv6)
import Data.List
import Data.Maybe
import Data.Word (Word8)
import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation.Cache
import Data.X509.Validation.Fingerprint
import Data.X509.Validation.Internal (safeCharacterToString)
import Data.X509.Validation.Signature
import Data.X509.Validation.Types
import Text.Read (readMaybe)
import Time.System

-- | Possible reason of certificate and chain failure.
--
-- The values 'InvalidName' and 'InvalidWildcard' are internal-only and are
-- never returned by the validation functions.  'NameMismatch' is returned
-- instead.
data FailedReason
    = -- | certificate contains an unknown critical extension
      UnknownCriticalExtension OID
    | -- | validity ends before checking time
      Expired
    | -- | validity starts after checking time
      InFuture
    | -- | certificate is self signed
      SelfSigned
    | -- | unknown Certificate Authority (CA)
      UnknownCA
    | -- | certificate is not allowed to sign
      NotAllowedToSign
    | -- | not a CA
      NotAnAuthority
    | -- | Violation of the optional Basic constraint's path length
      AuthorityTooDeep
    | -- | Certificate doesn't have any common name (CN)
      NoCommonName
    | -- | Invalid name in certificate
      InvalidName String
    | -- | connection name and certificate do not match
      NameMismatch String
    | -- | invalid wildcard in certificate
      InvalidWildcard
    | -- | the requested key usage is not compatible with the leaf certificate's key usage
      LeafKeyUsageNotAllowed
    | -- | the requested key purpose is not compatible with the leaf certificate's extended key usage
      LeafKeyPurposeNotAllowed
    | -- | Only authorized an X509.V3 certificate as leaf certificate.
      LeafNotV3
    | -- | empty chain of certificate
      EmptyChain
    | -- | the cache explicitely denied this certificate
      CacheSaysNo String
    | -- | signature failed
      InvalidSignature SignatureFailure
    deriving (Show, Eq)

-- | A set of checks to activate or parametrize to perform on certificates.
--
-- It's recommended to use 'defaultChecks' to create the structure,
-- to better cope with future changes or expansion of the structure.
data ValidationChecks = ValidationChecks
    { checkTimeValidity :: Bool
    -- ^ check time validity of every certificate in the chain.
    -- the make sure that current time is between each validity bounds
    -- in the certificate
    , checkAtTime :: Maybe DateTime
    -- ^ The time when the validity check happens. When set to Nothing,
    -- the current time will be used
    , checkStrictOrdering :: Bool
    -- ^ Check that no certificate is included that shouldn't be included.
    -- unfortunately despite the specification violation, a lots of
    -- real world server serves useless and usually old certificates
    -- that are not relevant to the certificate sent, in their chain.
    , checkCAConstraints :: Bool
    -- ^ Check that signing certificate got the CA basic constraint.
    -- this is absolutely not recommended to turn it off.
    , checkExhaustive :: Bool
    -- ^ Check the whole certificate chain without stopping at the first failure.
    -- Allow gathering a exhaustive list of failure reasons. if this is
    -- turn off, it's absolutely not safe to ignore a failed reason even it doesn't look serious
    -- (e.g. Expired) as other more serious checks would not have been performed.
    , checkLeafV3 :: Bool
    -- ^ Check that the leaf certificate is version 3. If disable, version 2 certificate
    -- is authorized in leaf position and key usage cannot be checked.
    , checkLeafKeyUsage :: [ExtKeyUsageFlag]
    -- ^ Check that the leaf certificate is authorized to be used for certain usage.
    -- If set to empty list no check are performed, otherwise all the flags is the list
    -- need to exists in the key usage extension. If the extension is not present,
    -- the check will pass and behave as if the certificate key is not restricted to
    -- any specific usage.
    , checkLeafKeyPurpose :: [ExtKeyUsagePurpose]
    -- ^ Check that the leaf certificate is authorized to be used for certain purpose.
    -- If set to empty list no check are performed, otherwise all the flags is the list
    -- need to exists in the extended key usage extension if present. If the extension is not
    -- present, then the check will pass and behave as if the certificate is not restricted
    -- to any specific purpose.
    , checkFQHN :: Bool
    -- ^ Check the top certificate names matching the fully qualified hostname (FQHN).
    -- it's not recommended to turn this check off, if no other name checks are performed.
    }
    deriving (Show, Eq)

-- | A set of hooks to manipulate the way the verification works.
--
-- BEWARE, it's easy to change behavior leading to compromised security.
data ValidationHooks = ValidationHooks
    { hookMatchSubjectIssuer :: DistinguishedName -> Certificate -> Bool
    -- ^ check whether a given issuer 'DistinguishedName' matches the subject
    -- 'DistinguishedName' of a candidate issuer certificate.
    , hookValidateTime :: DateTime -> Certificate -> [FailedReason]
    -- ^ check whether the certificate in the second argument is valid at the
    -- time provided in the first argument.  Return an empty list for success
    -- or else one or more failure reasons.
    , hookValidateName :: HostName -> Certificate -> [FailedReason]
    -- ^ validate the certificate leaf name with the DNS named used to connect
    , hookFilterReason :: [FailedReason] -> [FailedReason]
    -- ^ user filter to modify the list of failure reasons
    }

-- | Default checks to perform
--
-- The default checks are:
-- * Each certificate time is valid
-- * CA constraints is enforced for signing certificate
-- * Leaf certificate is X.509 v3
-- * Check that the FQHN match
defaultChecks :: ValidationChecks
defaultChecks =
    ValidationChecks
        { checkTimeValidity = True
        , checkAtTime = Nothing
        , checkStrictOrdering = False
        , checkCAConstraints = True
        , checkExhaustive = False
        , checkLeafV3 = True
        , checkLeafKeyUsage = []
        , checkLeafKeyPurpose = []
        , checkFQHN = True
        }

instance Default ValidationChecks where
    def = defaultChecks

-- | Default hooks in the validation process
defaultHooks :: ValidationHooks
defaultHooks =
    ValidationHooks
        { hookMatchSubjectIssuer = matchSI
        , hookValidateTime = validateTime
        , hookValidateName = validateCertificateName
        , hookFilterReason = id
        }

instance Default ValidationHooks where
    def = defaultHooks

-- | Validate using the default hooks and checks and the SHA256 mechanism as hashing mechanism
validateDefault
    :: CertificateStore
    -- ^ The trusted certificate store for CA
    -> ValidationCache
    -- ^ the validation cache callbacks
    -> ServiceID
    -- ^ identification of the connection
    -> CertificateChain
    -- ^ the certificate chain we want to validate
    -> IO [FailedReason]
    -- ^ the return failed reasons (empty list is no failure)
validateDefault = validate HashSHA256 defaultHooks defaultChecks

-- | X509 validation
--
-- the function first interrogate the cache and if the validation fail,
-- proper verification is done. If the verification pass, the
-- add to cache callback is called.
validate
    :: HashALG
    -- ^ the hash algorithm we want to use for hashing the leaf certificate
    -> ValidationHooks
    -- ^ Hooks to use
    -> ValidationChecks
    -- ^ Checks to do
    -> CertificateStore
    -- ^ The trusted certificate store for CA
    -> ValidationCache
    -- ^ the validation cache callbacks
    -> ServiceID
    -- ^ identification of the connection
    -> CertificateChain
    -- ^ the certificate chain we want to validate
    -> IO [FailedReason]
    -- ^ the return failed reasons (empty list is no failure)
validate _ _ _ _ _ _ (CertificateChain []) = return [EmptyChain]
validate hashAlg hooks checks store cache ident cc@(CertificateChain (top : _)) = do
    cacheResult <- (cacheQuery cache) ident fingerPrint (getCertificate top)
    case cacheResult of
        ValidationCachePass -> return []
        ValidationCacheDenied s -> return [CacheSaysNo s]
        ValidationCacheUnknown -> do
            validationTime <-
                maybe (timeConvert <$> timeCurrent) return $ checkAtTime checks
            let failedReasons = validatePure validationTime hooks checks store ident cc
            when (null failedReasons) $
                (cacheAdd cache) ident fingerPrint (getCertificate top)
            return failedReasons
  where
    fingerPrint = getFingerprint top hashAlg

-- | Validate a certificate chain with explicit pure parameters
validatePure
    :: DateTime
    -- ^ The time for which to check validity for
    -> ValidationHooks
    -- ^ Hooks to use
    -> ValidationChecks
    -- ^ Checks to do
    -> CertificateStore
    -- ^ The trusted certificate store for CA
    -> ServiceID
    -- ^ Identification of the connection
    -> CertificateChain
    -- ^ The certificate chain we want to validate
    -> [FailedReason]
    -- ^ the return failed reasons (empty list is no failure)
validatePure _ _ _ _ _ (CertificateChain []) = [EmptyChain]
validatePure validationTime hooks checks store (fqhn, _) (CertificateChain (top : rchain)) =
    hookFilterReason
        hooks
        (doLeafChecks |> doCheckChain 0 top rchain |> doCheckNameConst top rchain)
  where
    isExhaustive :: Bool
    isExhaustive = checkExhaustive checks

    (|>) :: [FailedReason] -> [FailedReason] -> [FailedReason]
    a |> b = exhaustive isExhaustive a b

    doLeafChecks :: [FailedReason]
    doLeafChecks =
        doNameCheck top
            ++ doV3Check topCert
            ++ doKeyUsageCheck topCert
      where
        topCert = getCertificate top

    doCheckChain
        :: Int -> SignedCertificate -> [SignedCertificate] -> [FailedReason]
    doCheckChain level current chain
        | level > maxChainDepth = [AuthorityTooDeep]
        | otherwise = doCheckChain' level current chain

    doCheckChain'
        :: Int -> SignedCertificate -> [SignedCertificate] -> [FailedReason]
    doCheckChain' level current chain =
        doCheckCertificate (getCertificate current)
            -- check if we have a trusted certificate in the store belonging to this issuer.
            |> ( case findCertificate (certIssuerDN cert) store of
                    Just trustedSignedCert -> checkSignature current trustedSignedCert
                    Nothing
                        | isSelfSigned cert -> [SelfSigned] |> checkSignature current current
                        | null chain -> [UnknownCA]
                        | otherwise ->
                            case findIssuer (certIssuerDN cert) chain of
                                Nothing -> [UnknownCA]
                                Just (issuer, remaining) ->
                                    checkCA level (getCertificate issuer)
                                        |> checkSignature current issuer
                                        |> doCheckChain (level + 1) issuer remaining
               )
      where
        cert :: Certificate
        cert = getCertificate current
    -- in a strict ordering check the next certificate has to be the issuer.
    -- otherwise we dynamically reorder the chain to have the necessary certificate
    findIssuer
        :: DistinguishedName
        -> [SignedCertificate]
        -> Maybe (SignedCertificate, [SignedCertificate])
    findIssuer issuerDN chain
        | checkStrictOrdering checks =
            case chain of
                [] -> error "not possible"
                (c : cs)
                    | matchSubjectIdentifier issuerDN (getCertificate c) -> Just (c, cs)
                    | otherwise -> Nothing
        | otherwise =
            case break (matchSubjectIdentifier issuerDN . getCertificate) chain of
                (before, x : after) -> Just (x, before ++ after)
                _ -> Nothing
    matchSubjectIdentifier :: DistinguishedName -> Certificate -> Bool
    matchSubjectIdentifier = hookMatchSubjectIssuer hooks

    -- we check here that the certificate is allowed to be a certificate
    -- authority, by checking the BasicConstraint extension. We also check,
    -- if present the key usage extension for ability to cert sign. If this
    -- extension is not present, then according to RFC 5280, it's safe to
    -- assume that only cert sign (and crl sign) are allowed by this certificate.
    checkCA :: Int -> Certificate -> [FailedReason]
    checkCA level cert
        | not (checkCAConstraints checks) = []
        | and [allowedSign, allowedCA, allowedDepth] = []
        | otherwise =
            (if allowedSign then [] else [NotAllowedToSign])
                ++ (if allowedCA then [] else [NotAnAuthority])
                ++ (if allowedDepth then [] else [AuthorityTooDeep])
      where
        extensions = certExtensions cert
        -- an extension that cannot be decoded is not treated as absent
        allowedSign = case extensionGetE extensions of
            Just (Right (ExtKeyUsage flags)) -> KeyUsage_keyCertSign `elem` flags
            Just (Left _) -> False
            Nothing -> True
        (allowedCA, pathLen) = case extensionGetE extensions of
            Just (Right (ExtBasicConstraints True pl)) -> (True, pl)
            _ -> (False, Nothing)
        allowedDepth = case pathLen of
            Nothing -> True
            Just pl
                | fromIntegral pl >= level -> True
                | otherwise -> False

    doNameCheck :: SignedCertificate -> [FailedReason]
    doNameCheck cert
        | not (checkFQHN checks) = []
        | otherwise = (hookValidateName hooks) fqhn (getCertificate cert)

    doV3Check :: Certificate -> [FailedReason]
    doV3Check cert
        | checkLeafV3 checks = case certVersion cert of
            2 {- confusingly it means X509.V3 -} -> []
            _ -> [LeafNotV3]
        | otherwise = []

    doKeyUsageCheck :: Certificate -> [FailedReason]
    doKeyUsageCheck cert =
        compareListIfExistAndNotNull
            mflags
            (checkLeafKeyUsage checks)
            LeafKeyUsageNotAllowed
            ++ compareListIfExistAndNotNull
                mpurposes
                (checkLeafKeyPurpose checks)
                LeafKeyPurposeNotAllowed
      where
        mflags = case extensionGetE $ certExtensions cert of
            Just (Right (ExtKeyUsage keyflags)) -> Just (Right keyflags)
            Just (Left e) -> Just (Left e)
            Nothing -> Nothing
        mpurposes = case extensionGetE $ certExtensions cert of
            Just (Right (ExtExtendedKeyUsage keyPurposes)) -> Just (Right keyPurposes)
            Just (Left e) -> Just (Left e)
            Nothing -> Nothing
        -- compare a list of things to an expected list. the expected list
        -- need to be a subset of the list (if not Nothing), and is not will
        -- return [err]. An undecodable extension always fails.
        compareListIfExistAndNotNull Nothing _ _ = []
        compareListIfExistAndNotNull (Just (Left _)) _ err = [err]
        compareListIfExistAndNotNull (Just (Right list)) expected err
            | null expected = []
            | intersect expected list == expected = []
            | otherwise = [err]

    doCheckCertificate :: Certificate -> [FailedReason]
    doCheckCertificate cert =
        exhaustiveList
            (checkExhaustive checks)
            [ (checkTimeValidity checks, hookValidateTime hooks validationTime cert)
            , (True, doCriticalExtensionSweep cert)
            ]
    -- check signature of 'signedCert' against the 'signingCert'
    checkSignature
        :: SignedCertificate -> SignedCertificate -> [FailedReason]
    checkSignature signedCert signingCert =
        case verifySignedSignature signedCert (certPubKey $ getCertificate signingCert) of
            SignaturePass -> []
            SignatureFailed r -> [InvalidSignature r]

    -- Failures to build the chain are reported by 'doCheckChain'.
    doCheckNameConst :: SignedCertificate -> [SignedCertificate] -> [FailedReason]
    doCheckNameConst current0 chain0 = case loop (0 :: Int) current0 chain0 [] of
        Left errs -> errs
        Right ts -> checkNameConstraints ts
      where
        loop level current chain acc
            | level > maxChainDepth = Left []
            | otherwise = case findCertificate issuer store of
                Just anchor -> Right $ getNameConstSpec (getCertificate anchor) False : spec : acc
                Nothing
                    | null chain -> Left []
                    | otherwise -> case findIssuer issuer chain of
                        Nothing -> Left []
                        Just (issuer', remaining) -> loop (level + 1) issuer' remaining (spec : acc)
          where
            cert = getCertificate current
            issuer = certIssuerDN cert
            isLeaf = level == 0
            spec = getNameConstSpec cert (isLeaf && checkFQHN checks)

isSelfSigned :: Certificate -> Bool
isSelfSigned cert = certSubjectDN cert == certIssuerDN cert

-- | The maximum number of CA certificates followed from the leaf.
maxChainDepth :: Int
maxChainDepth = 20

data NameConstSpec = NameConstSpec
    { ncNames :: Either String [AltName]
    -- ^ names subject to name constraints
    , ncExt :: Either String (Maybe ExtNameConstraints)
    , ncSelfIssued :: Bool
    }

-- | The second argument tells whether the CN is used as a host name.
getNameConstSpec :: Certificate -> Bool -> NameConstSpec
getNameConstSpec cert useCN =
    NameConstSpec
        { ncNames = names
        , ncExt = maybe (Right Nothing) (fmap Just) $ extensionGetE exts
        , ncSelfIssued = isSelfSigned cert
        }
  where
    exts = certExtensions cert
    subjDN = certSubjectDN cert
    subj = [AltNameDN subjDN | not (null (getDistinguishedElements subjDN))]
    -- RFC 5280: without SAN, emailAddress in the subject is an rfc822Name
    emails =
        [ AltNameRFC822 e
        | (oid, v) <- getDistinguishedElements subjDN
        , oid == [1, 2, 840, 113549, 1, 9, 1]
        , Just e <- [safeCharacterToString v]
        ]
    cn
        | useCN = case getNames cert of
            Right (Just name, []) -> [maybe (AltNameDNS name) ipToAltName (parseIPAddress name)]
            _ -> []
        | otherwise = []
    names = case extensionGetE exts of
        Nothing -> Right (subj ++ emails ++ cn)
        Just (Right (ExtSubjectAltName alts)) -> Right (subj ++ alts ++ cn)
        Just (Left e) -> Left e

ipToAltName :: IPAddress -> AltName
ipToAltName (IPv4Address ip) = AltNameIP $ B.pack $ map fromIntegral $ fromIPv4 ip
ipToAltName (IPv6Address ip) = AltNameIP $ B.pack $ map fromIntegral $ fromIPv6b ip

-- | Validate that the current time is between validity bounds
validateTime :: DateTime -> Certificate -> [FailedReason]
validateTime currentTime cert
    | currentTime < before = [InFuture]
    | currentTime > after = [Expired]
    | otherwise = []
  where
    (before, after) = certValidity cert

-- | 'Left' if the SAN extension is present but cannot be decoded.
getNames :: Certificate -> Either String (Maybe String, [String])
getNames cert = case extensionGetE $ certExtensions cert of
    Just (Left e) -> Left e
    Just (Right san) -> Right (commonName, toAltName san)
    Nothing -> Right (commonName, [])
  where
    commonName = getDnElement DnCommonName (certSubjectDN cert) >>= safeCharacterToString
    toAltName (ExtSubjectAltName names) = catMaybes $ map unAltName names
      where
        unAltName (AltNameDNS s) = Just s
        unAltName _ = Nothing

data IPAddress
    = IPv4Address IPv4
    | IPv6Address IPv6
    deriving (Eq)

getIPs :: Certificate -> [IPAddress]
getIPs cert = fromMaybe [] (toAltName <$> (extensionGet $ certExtensions cert))
  where
    toAltName (ExtSubjectAltName names) = catMaybes $ map unAltName names

    unAltName (AltNameIP s) = case unpack s of
        [a, b, c, d] -> Just $ IPv4Address $ toIPv4 $ fmap fromIntegral [a, b, c, d]
        [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] ->
            Just $
                IPv6Address $
                    toIPv6
                        [ fuse a b
                        , fuse c d
                        , fuse e f
                        , fuse g h
                        , fuse i j
                        , fuse k l
                        , fuse m n
                        , fuse o p
                        ]
        _ -> Nothing
    unAltName _ = Nothing

    fuse :: Word8 -> Word8 -> Int
    fuse a b = shiftL (fromIntegral a) 8 .|. (fromIntegral b)

parseIPAddress :: HostName -> Maybe IPAddress
parseIPAddress (readMaybe -> Just ipV4) = Just $ IPv4Address ipV4
parseIPAddress (readMaybe -> Just ipV6) = Just $ IPv6Address ipV6
parseIPAddress _ = Nothing

-- | Validate that the fqhn is matched by at least one name in the certificate.
-- If the subjectAltname extension is present, then the certificate commonName
-- is ignored, and only the DNS names and IP Addresses, if any, in the
-- subjectAltName are considered.  Otherwise, the commonName from the subjectDN
-- is used.
--
-- If the subjectAltName extension cannot be decoded, the name never matches.
--
-- Note that DNS names in the subjectAltName are in IDNA A-label form. If the
-- destination hostname is a UTF-8 name, it must be provided to the TLS context
-- in (non-transitional) IDNA2008 A-label form.
validateCertificateName :: HostName -> Certificate -> [FailedReason]
validateCertificateName fqhn cert = case getNames cert of
    Left _ -> [NameMismatch fqhn]
    Right names -> validateNames fqhn cert names

validateNames
    :: HostName -> Certificate -> (Maybe String, [String]) -> [FailedReason]
validateNames fqhn cert (commonName, altNames)
    | not $ null altNames =
        case parseIPAddress fqhn of
            Nothing -> findMatch [] $ map matchDomain altNames
            Just ip ->
                if elem ip (getIPs cert)
                    then []
                    else [NameMismatch fqhn]
    | otherwise =
        case commonName of
            Nothing -> [NoCommonName]
            Just cn -> findMatch [] $ [matchDomain cn]
  where
    findMatch :: [FailedReason] -> [[FailedReason]] -> [FailedReason]
    findMatch _ [] = [NameMismatch fqhn]
    findMatch _ ([] : _) = []
    findMatch acc (_ : xs) = findMatch acc xs

    matchDomain :: String -> [FailedReason]
    matchDomain name = case splitDot name of
        l
            | any (== "") l -> [InvalidName name]
            | head l == "*" -> wildcardMatch (drop 1 l)
            | l == splitDot fqhn -> [] -- success: we got a match
            | otherwise -> [NameMismatch fqhn]

    -- A wildcard matches a single domain name component.
    --
    -- e.g. *.server.com will match www.server.com but not www.m.server.com
    --
    -- Only 1 wildcard is valid and only for the left-most component. If
    -- used at other positions or if multiples are present
    -- they won't have a wildcard meaning but will be match as normal star
    -- character to the fqhn and inevitably will fail.
    --
    -- e.g. *.*.server.com will try to litteraly match the '*' subdomain of server.com
    --
    -- Also '*' is not accepted as a valid wildcard
    wildcardMatch l
        | null l = [InvalidWildcard] -- '*' is always invalid
        | l == drop 1 (splitDot fqhn) = [] -- success: we got a match
        | otherwise = [NameMismatch fqhn]

    splitDot :: String -> [String]
    splitDot [] = [""]
    splitDot x =
        let (y, z) = break (== '.') x
         in map toLower y : (if z == "" then [] else splitDot $ drop 1 z)

-- | return true if the 'subject' certificate's issuer match
-- the 'issuer' certificate's subject
matchSI :: DistinguishedName -> Certificate -> Bool
matchSI issuerDN issuer = certSubjectDN issuer == issuerDN

exhaustive :: Bool -> [FailedReason] -> [FailedReason] -> [FailedReason]
exhaustive isExhaustive l1 l2
    | null l1 = l2
    | isExhaustive = l1 ++ l2
    | otherwise = l1

exhaustiveList :: Bool -> [(Bool, [FailedReason])] -> [FailedReason]
exhaustiveList _ [] = []
exhaustiveList isExhaustive ((performCheck, c) : cs)
    | performCheck = exhaustive isExhaustive c (exhaustiveList isExhaustive cs)
    | otherwise = exhaustiveList isExhaustive cs

-- | Name constraints accumulated along the chain (RFC 5280 6.1):
-- a name must be in a permitted subtree of every level that has one
-- and must not be in any excluded subtree.
data NameConstState = NameConstState [[GeneralSubtree]] [GeneralSubtree]

-- | The first element is the trust anchor and the last is the leaf.
checkNameConstraints :: [NameConstSpec] -> [FailedReason]
checkNameConstraints [] = []
checkNameConstraints (anchor : specs0) =
    either id (\st -> loop st specs0) $ addNameConst (NameConstState [] []) anchor
  where
    loop _ [] = []
    loop st (spec : specs) =
        check ++ case specs of
            [] -> []
            _ -> either id (\st' -> loop st' specs) $ addNameConst st spec
      where
        -- self-issued intermediates are exempt but the leaf is not
        check
            | ncSelfIssued spec && not (null specs) = []
            | otherwise = validateNames' st (ncNames spec)

addNameConst
    :: NameConstState -> NameConstSpec -> Either [FailedReason] NameConstState
addNameConst st@(NameConstState permitted excluded) spec = case ncExt spec of
    Left e -> Left [InvalidName $ "NameConstraints: " ++ e]
    Right Nothing -> Right st
    Right (Just (ExtNameConstraints p e)) ->
        Right $ NameConstState ([p | not (null p)] ++ permitted) (e ++ excluded)

validateNames' :: NameConstState -> Either String [AltName] -> [FailedReason]
validateNames' (NameConstState [] []) _ = []
validateNames' _ (Left e) = [InvalidName $ "SubjectAltName: " ++ e]
validateNames' (NameConstState permitted excluded) (Right altNames) =
    concatMap inc altNames ++ concatMap exc altNames
  where
    inc a
        | all (nsMatch a) permitted = []
        | otherwise = [InvalidName $ show a]
    exc a
        | nsNotMatch a excluded = []
        | otherwise = [InvalidName $ show a]

data NameMatch = NotApplicable | Matched | NotMatched | Unsupported
    deriving (Eq)

-- | A permitted subtree list is satisfied if the name is in one of them
-- or if none of them is of the same type as the name.
nsMatch :: AltName -> [GeneralSubtree] -> Bool
nsMatch a gs = any (== Matched) rs || all (== NotApplicable) rs
  where
    rs = map (matchSubtree False a) gs

nsNotMatch :: AltName -> [GeneralSubtree] -> Bool
nsNotMatch a = all ((`elem` [NotApplicable, NotMatched]) . matchSubtree True a)

-- | The first argument tells whether the subtree is an excluded one.
-- Unsupported forms count as matched when excluded and as not matched
-- when permitted.
matchSubtree :: Bool -> AltName -> GeneralSubtree -> NameMatch
matchSubtree isExcluded name (GeneralSubtree base _ _) = case (name, base) of
    (AltNameDNS n, AltNameDNS c) ->
        toMatch $ dnsInSubtree n c || (isExcluded && wildcardCovers n c)
    (AltNameDN n, AltNameDN c) -> toMatch $ dnInSubtree n c
    (AltNameIP n, AltNameIP c) -> ipInSubtree n c
    (AltNameRFC822 n, AltNameRFC822 c) -> maybe Unsupported toMatch $ emailInSubtree n c
    (AltNameURI n, AltNameURI c) -> maybe Unsupported (toMatch . (`hostInSubtree` c)) $ uriHost n
    (AltNameXMPP _, AltNameXMPP _) -> Unsupported
    (AltNameDNSSRV _, AltNameDNSSRV _) -> Unsupported
    _ -> NotApplicable
  where
    toMatch b = if b then Matched else NotMatched

-- | "example.com" covers itself and its subdomains, ".example.com" only
-- its subdomains.  Compared case-insensitively.
dnsInSubtree :: String -> String -> Bool
dnsInSubtree n c
    | null c' = True
    | "." `isPrefixOf` c' = c' `isSuffixOf` n'
    | otherwise = n' == c' || ('.' : c') `isSuffixOf` n'
  where
    n' = map toLower n
    c' = map toLower c

-- | Whether a wildcard name such as "*.example.com" may stand for a name
-- in the subtree, e.g. "www.example.com".
wildcardCovers :: String -> String -> Bool
wildcardCovers n c = case stripPrefix "*." (map toLower n) of
    Just rest ->
        let c' = map toLower c
            label = take (length c' - length rest - 1) c'
         in not (null label)
                && '.' `notElem` label
                && ('.' : rest) `isSuffixOf` c'
    Nothing -> False

hostInSubtree :: String -> String -> Bool
hostInSubtree h c
    | "." `isPrefixOf` c' = c' `isSuffixOf` h'
    | otherwise = h' == c'
  where
    h' = map toLower h
    c' = map toLower c

-- | "user@host" matches exactly, "host" matches all mailboxes on the host
-- and ".example.com" all mailboxes on its subdomains.
emailInSubtree :: String -> String -> Maybe Bool
emailInSubtree n c = case breakAt n of
    Just (local, host) -> Just $ case breakAt c of
        Just (cLocal, cHost) -> local == cLocal && map toLower host == map toLower cHost
        Nothing -> hostInSubtree host c
    Nothing -> Nothing
  where
    breakAt x = case break (== '@') (reverse x) of
        (rhost, '@' : rlocal) -> Just (reverse rlocal, reverse rhost)
        _ -> Nothing

-- | The host of a URI with an authority; 'Nothing' for IP literals.
uriHost :: String -> Maybe String
uriHost uri = case break (== ':') uri of
    (_, ':' : '/' : '/' : rest) ->
        let authority = takeWhile (`notElem` ("/?#" :: String)) rest
            hostport = reverse $ takeWhile (/= '@') $ reverse authority
            host = takeWhile (/= ':') hostport
         in if null host || "[" `isPrefixOf` hostport || isJust (parseIPAddress host)
                then Nothing
                else Just host
    _ -> Nothing

-- | The subtree is a prefix of the name.  Attribute values are compared
-- case-insensitively with whitespace folded.
dnInSubtree :: DistinguishedName -> DistinguishedName -> Bool
dnInSubtree (DistinguishedName n) (DistinguishedName c) =
    length c <= length n && and (zipWith eq n c)
  where
    eq (o1, v1) (o2, v2) = o1 == o2 && norm v1 == norm v2
    norm v = case safeCharacterToString v of
        Just str -> Right $ unwords $ words $ map toLower str
        Nothing -> Left v

-- | An IPv4 or IPv6 address against an address with a mask.
ipInSubtree :: ByteString -> ByteString -> NameMatch
ipInSubtree n c
    | B.length c /= 8 && B.length c /= 32 = Unsupported
    | B.length n /= 4 && B.length n /= 16 = Unsupported
    | 2 * B.length n /= B.length c = NotMatched
    | otherwise =
        if and
            ( zipWith3
                (\x a m -> x .&. m == a .&. m)
                (B.unpack n)
                (B.unpack addr)
                (B.unpack mask)
            )
            then Matched
            else NotMatched
  where
    (addr, mask) = B.splitAt (B.length n) c

doCriticalExtensionSweep :: Certificate -> [FailedReason]
doCriticalExtensionSweep cert = case mexts of
    Nothing -> []
    Just exts ->
        [ UnknownCriticalExtension oid
        | ExtensionRaw oid critical _ <- exts
        , critical
        , oid `notElem` recognizedOIDs
        ]
  where
    Extensions mexts = certExtensions cert
