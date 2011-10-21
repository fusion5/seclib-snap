{-
    Convenience module to export functions that are allowed
    to be used by untrusted code.

    Can be imported by untrusted code: Yes
    Type: Trusted
-}
module SecLib.SecLib (
    SnapSec
  , Sec

  , sec
  , up
  , lift
  , open
  , plug

  , method
  , runRoute
  , redirect

  , getRequest
  , modifyResponse

  , writeBS
  , writeLBS

  , cookiePKey
  , cookiePKeySnap
) where

import SecLib.Sec hiding (up)
import SecLib.SnapSec

