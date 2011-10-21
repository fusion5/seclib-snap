{- 
    Module containing types used to define pure hatches
    as well as normal hatches in the SnapSec monad.

    Can be imported by untrusted code: No
    Type: Trusted
-}

module SecLib.DeclCombinatorsTypes (
    Hatch
) where

import SecLib.Sec     (Sec)
import SecLib.SnapSec (SnapSec)

type Hatch h l a b = Sec h a -> SnapSec l b

