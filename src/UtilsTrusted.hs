{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

{-
    Module containing helper functions used by controllers.
    Functons that do IO, or otherwise sensitive information, 
    etc, should be defined here.

    Can be imported by untrusted code: Yes
    Type: Trusted
-}

module UtilsTrusted (
    getNow
  , getHttpNow
  , getLogoutCookie
  , getLoginCookie
) where

import Data.Time.Clock 
import Data.Time.Clock.POSIX 

import Foreign.C.Types

import Snap.Types 
import SecLib.SnapSec 

getNow = liftIO $ getCurrentTime

-- Returns a bytestring of http formatted time
getHttpNow = do
    now <- getNow
    liftIO $ formatHttpTime $ toCTime now

toCTime :: UTCTime -> CTime
toCTime = fromInteger
        . truncate 
        . utcTimeToPOSIXSeconds

{- Login cookie generation and verification:
   This is trusted code, as we don't want 
   to make it possible to write code that modifies the expiration 
   cookie time for example, and certainly not allow code to return 
   falsified cookies that would give users too high permissions.
-}

getLogoutCookie now =
    Cookie {
          cookieName    = "level"
        , cookieValue   = ""
        , cookieExpires = Just now
        , cookieDomain  = Nothing -- Use current domain
        , cookiePath    = Just "/" 
        }

getLoginCookie now cookieStr = 
    Cookie {
          cookieName    = "level"
        , cookieValue   = cookieStr 
        , cookieExpires = Just (addUTCTime twoWeeks now)
        , cookieDomain  = Nothing -- Use current domain
        , cookiePath    = Just "/" 
        }
    where twoWeeks = fromRational 3600 * 24 * 14

