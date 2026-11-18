{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Data.X509.CertificateStore (
    CertificateStore,
    isEmptyCertificateStore,
    makeCertificateStore,
    readCertificateStore,
    readCertificates,

    -- * Queries
    findCertificate,
    findCertificates,
    listCertificates,
) where

import Data.Char (isDigit, isHexDigit)
import Data.Either (rights)
import qualified Data.List as L
#if !(MIN_VERSION_base(4,11,0))
import           Data.Semigroup
#endif
import qualified Control.Exception as E
import Control.Monad (filterM)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.Map as M
import Data.PEM (PEM, pemContent, pemName, pemParseBS)
import Data.X509
import System.Directory (
    doesDirectoryExist,
    doesFileExist,
    getDirectoryContents,
    pathIsSymbolicLink,
 )
import System.FilePath (takeFileName, (</>))
import qualified System.IO.Error as E
#if !defined(mingw32_HOST_OS)
import System.Posix.Files (getFileStatus, isRegularFile)
#endif

-- | A Collection of certificate or store of certificates.  Several
-- certificates may have the same subject, which is compared in its
-- canonical form.
data CertificateStore
    = CertificateStore (M.Map DistinguishedName [SignedCertificate])
    | CertificateStores [CertificateStore]

isEmptyCertificateStore :: CertificateStore -> Bool
isEmptyCertificateStore (CertificateStore m) = M.null m
isEmptyCertificateStore (CertificateStores l) = all isEmptyCertificateStore l

#if MIN_VERSION_base(4,9,0)
instance Semigroup CertificateStore where
    (<>) = append
#endif

instance Monoid CertificateStore where
    mempty = CertificateStore M.empty
#if !(MIN_VERSION_base(4,11,0))
    mappend = append
#endif

append :: CertificateStore -> CertificateStore -> CertificateStore
append s1@(CertificateStore _) s2@(CertificateStore _) = CertificateStores [s1, s2]
append (CertificateStores l) s2@(CertificateStore _) = CertificateStores (l ++ [s2])
append s1@(CertificateStore _) (CertificateStores l) = CertificateStores ([s1] ++ l)
append (CertificateStores l1) (CertificateStores l2) = CertificateStores (l1 ++ l2)

-- | Create a certificate store out of a list of X509 certificate
makeCertificateStore :: [SignedCertificate] -> CertificateStore
makeCertificateStore = CertificateStore . L.foldl' accumulate M.empty
  where
    -- the latest certificate comes first
    accumulate m x509 = M.insertWith add (subjectKey x509) [x509] m
    add new old = new ++ filter (`notElem` new) old
    subjectKey = canonicalDistinguishedName . certSubjectDN . getCertificate

-- | Find a certificate using the subject distinguished name.  If several
-- certificates have the subject, the one added last is returned.
findCertificate
    :: DistinguishedName -> CertificateStore -> Maybe SignedCertificate
findCertificate dn store = case findCertificates dn store of
    c : _ -> Just c
    [] -> Nothing

-- | Find all certificates with the subject distinguished name.
findCertificates
    :: DistinguishedName -> CertificateStore -> [SignedCertificate]
findCertificates dn = lookupIn
  where
    key = canonicalDistinguishedName dn
    lookupIn (CertificateStore m) = M.findWithDefault [] key m
    lookupIn (CertificateStores l) = concatMap lookupIn l

-- | List all certificates in a store
listCertificates :: CertificateStore -> [SignedCertificate]
listCertificates (CertificateStore store) = concat $ M.elems store
listCertificates (CertificateStores l) = concatMap listCertificates l

-- | Create certificate store by reading certificates from file or directory
--
-- This function can be used to read multiple certificates from either
-- single file (multiple PEM formatted certificates concanated) or
-- directory (one certificate per file, file names are hashes from
-- certificate).
readCertificateStore :: FilePath -> IO (Maybe CertificateStore)
readCertificateStore path = do
    isDir <- doesDirectoryExist path
    isFile <- doesFileExist path
    wrapStore
        <$> (if isDir then makeDirStore else if isFile then makeFileStore else return [])
  where
    wrapStore :: [SignedCertificate] -> Maybe CertificateStore
    wrapStore [] = Nothing
    wrapStore l = Just $ makeCertificateStore l

    makeFileStore = readCertificates path
    makeDirStore = do
        certFiles <- listDirectoryCerts path
        concat <$> mapM readCertificates certFiles

-- Try to read certificate from the content of a file.
--
-- The file may contains multiple certificates.  Only the PEM blocks
-- labeled CERTIFICATE are used: a TRUSTED CERTIFICATE block carries
-- OpenSSL trust settings, which are not interpreted.  Broken blocks
-- are skipped.
readCertificates :: FilePath -> IO [SignedCertificate]
readCertificates file =
    E.catchIOError
        (rights . map getCert . filter isCert . pemBlocks <$> B.readFile file)
        skipIOError
  where
    isCert pem = pemName pem `elem` ["CERTIFICATE", "X509 CERTIFICATE"]
    getCert = decodeSignedCertificate . pemContent
    skipIOError :: E.IOException -> IO [SignedCertificate]
    skipIOError _ = return []

-- | Parse PEM blocks one by one so that a broken block does not
-- discard the others.
pemBlocks :: B.ByteString -> [PEM]
pemBlocks = go . BC.lines
  where
    go ls = case dropWhile (not . B.isPrefixOf "-----BEGIN ") ls of
        [] -> []
        begin : rest -> case break (B.isPrefixOf "-----END ") rest of
            (body, end : rest') ->
                either (const []) id (pemParseBS $ BC.unlines (begin : body ++ [end]))
                    ++ go rest'
            _ -> []

-- List all the path susceptible to contains a certificate in a directory
--
-- if the parameter is not a directory, hilarity follows.
listDirectoryCerts :: FilePath -> IO [FilePath]
listDirectoryCerts path =
    getDirContents >>= filterM keep
  where
    -- hashed names are usually symbolic links to other files in the
    -- directory, but are regular files on Android, for instance
    keep p = do
        regular <- isRegular p
        if regular && isHashedFile (takeFileName p)
            then not <$> pathIsSymbolicLink p
            else return regular
    isHashedFile s =
        length s == 10
            && isDigit (s !! 9)
            && (s !! 8) == '.'
            && all isHexDigit (take 8 s)
    isCert x = not $ L.isPrefixOf "." x

    getDirContents =
        E.catchIOError
            (map (path </>) . filter isCert <$> getDirectoryContents path)
            emptyPaths
      where
        emptyPaths :: E.IOException -> IO [FilePath]
        emptyPaths _ = return []

-- | Whether the path is a regular file, following symbolic links.
isRegular :: FilePath -> IO Bool
#if defined(mingw32_HOST_OS)
isRegular = doesFileExist
#else
isRegular p =
    E.catchIOError (isRegularFile <$> getFileStatus p) (\_ -> return False)
#endif
