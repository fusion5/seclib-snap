{- 
    Module containing combinators used to define pure hatches
    as well as normal hatches in the SnapSec monad.

    Can be imported by untrusted code: No
    Type: Trusted
-}

module SecLib.DeclCombinators (
    hatch
)where

import SecLib.Sec (reveal)
import SecLib.Lattice 
import SecLib.DeclCombinatorsTypes

hatch :: Less l h => (a -> b) -> Hatch h l a b  
hatch f = \sa -> return (f (reveal sa))
