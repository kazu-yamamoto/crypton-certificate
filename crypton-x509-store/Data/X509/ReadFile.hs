{-# LANGUAGE CPP #-}

module Data.X509.ReadFile (
    readFileCloexec,
) where

#ifndef MIN_VERSION_unix
#define MIN_VERSION_unix(x, y, z) 0
#endif

import qualified Data.ByteString as B
#if defined(MIN_VERSION_unix) && MIN_VERSION_unix(2,8,0)
import qualified Control.Exception as E
import System.IO (hClose)
import System.Posix.IO
#endif

-- | Read a whole file strictly.  The file descriptor is not inherited
-- by child processes (when unix >= 2.8 is available).
readFileCloexec :: FilePath -> IO B.ByteString
#if defined(MIN_VERSION_unix) && MIN_VERSION_unix(2,8,0)
readFileCloexec path =
    E.bracket
        (openFd path ReadOnly defaultFileFlags{cloexec = True} >>= fdToHandle)
        hClose
        B.hGetContents
#else
readFileCloexec = B.readFile
#endif
