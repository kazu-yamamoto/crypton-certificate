{-# LANGUAGE CPP #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module      : Data.X509.DistinguishedName
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X.509 Distinguished names types and functions
module Data.X509.DistinguishedName (
    DistinguishedName (DistinguishedName, getDistinguishedElements),
    RelativeDistinguishedName,
    getRDNs,
    fromRDNs,
    DistinguishedNameInner (..),
    ASN1CharacterString (..),
    -- Distinguished Name Elements
    DnElement (..),
    getDnElement,
    canonicalDistinguishedName,
) where

#if !(MIN_VERSION_base(4,11,0))
import           Data.Semigroup
#endif
import Data.ASN1.Types
import Data.Char (toLower)
import Data.List (sort)
import Data.X509.Internal

-- | A sequence of relative distinguished names.  The constructor is
-- hidden; use 'getRDNs' and 'fromRDNs', or the 'DistinguishedName' pattern
-- for names without multi-valued RDNs.
newtype DistinguishedName = RDNSequence [RelativeDistinguishedName]
    deriving (Show, Eq, Ord)

-- | A set of attribute types and values, usually with one element.
type RelativeDistinguishedName = [(OID, ASN1CharacterString)]

-- | The relative distinguished names.
getRDNs :: DistinguishedName -> [RelativeDistinguishedName]
getRDNs (RDNSequence rdns) = rdns

-- | A name from relative distinguished names.
fromRDNs :: [RelativeDistinguishedName] -> DistinguishedName
fromRDNs = RDNSequence

-- | All attributes in order, flattening multi-valued RDNs.  Constructing
-- makes one RDN per attribute.
pattern DistinguishedName
    :: [(OID, ASN1CharacterString)] -> DistinguishedName
pattern DistinguishedName{getDistinguishedElements} <-
    (concat . getRDNs -> getDistinguishedElements)
    where
        DistinguishedName els = RDNSequence (map (: []) els)

{-# COMPLETE DistinguishedName #-}

-- | Elements commonly available in a 'DistinguishedName' structure
data DnElement
    = -- | CN
      DnCommonName
    | -- | Country
      DnCountry
    | -- | O
      DnOrganization
    | -- | OU
      DnOrganizationUnit
    | -- | Email Address (legacy)
      DnEmailAddress
    deriving (Show, Eq)

instance OIDable DnElement where
    getObjectID DnCommonName = [2, 5, 4, 3]
    getObjectID DnCountry = [2, 5, 4, 6]
    getObjectID DnOrganization = [2, 5, 4, 10]
    getObjectID DnOrganizationUnit = [2, 5, 4, 11]
    getObjectID DnEmailAddress = [1, 2, 840, 113549, 1, 9, 1]

-- | Try to get a specific element in a 'DistinguishedName' structure
getDnElement :: DnElement -> DistinguishedName -> Maybe ASN1CharacterString
getDnElement element dn = lookup (getObjectID element) $ getDistinguishedElements dn

-- | A form for comparing names (RFC 5280 7.1): string values are
-- converted to UTF8String, lower-cased and whitespace is folded, and the
-- attributes of each RDN are sorted.  Values
-- that cannot be decoded are kept.
canonicalDistinguishedName :: DistinguishedName -> DistinguishedName
canonicalDistinguishedName (RDNSequence rdns) =
    RDNSequence [sort [(oid, canon v) | (oid, v) <- rdn] | rdn <- rdns]
  where
    canon v = case safeCharacterToString v of
        Just str -> asn1CharacterString UTF8 $ unwords $ words $ map toLower str
        Nothing -> v

-- | Only use to encode a DistinguishedName without including it in a
-- Sequence
newtype DistinguishedNameInner = DistinguishedNameInner DistinguishedName
    deriving (Show, Eq)

#if MIN_VERSION_base(4,9,0)
instance Semigroup DistinguishedName where
    RDNSequence l1 <> RDNSequence l2 = RDNSequence (l1++l2)
#endif

instance Monoid DistinguishedName where
    mempty = RDNSequence []
#if !(MIN_VERSION_base(4,11,0))
    mappend (RDNSequence l1) (RDNSequence l2) = RDNSequence (l1++l2)
#endif

instance ASN1Object DistinguishedName where
    toASN1 dn = \xs -> encodeDN dn ++ xs
    fromASN1 = runParseASN1State parseDN

-- FIXME parseDNInner in fromASN1 is probably wrong as we don't have a container
-- and thus hasNext should be replaced by a isFinished clause.
instance ASN1Object DistinguishedNameInner where
    toASN1 (DistinguishedNameInner dn) = \xs -> encodeDNinner dn ++ xs
    fromASN1 =
        runParseASN1State (DistinguishedNameInner . RDNSequence <$> parseDNInner)

parseDN :: ParseASN1 DistinguishedName
parseDN = RDNSequence <$> onNextContainer Sequence parseDNInner

parseDNInner :: ParseASN1 [RelativeDistinguishedName]
parseDNInner = getMany parseOneDN

parseOneDN :: ParseASN1 RelativeDistinguishedName
parseOneDN = onNextContainer Set $ getMany $ do
    s <- getNextContainer Sequence
    case s of
        [OID oid, ASN1String cs] -> return (oid, cs)
        _ ->
            throwParseError ("expecting [OID,String] got " ++ show s)

encodeDNinner :: DistinguishedName -> [ASN1]
encodeDNinner (RDNSequence rdns) = concatMap rdnSet rdns
  where
    rdnSet rdn = asn1Container Set $ concatMap atv rdn
    atv (oid, cs) = asn1Container Sequence [OID oid, ASN1String cs]

encodeDN :: DistinguishedName -> [ASN1]
encodeDN dn = asn1Container Sequence $ encodeDNinner dn
