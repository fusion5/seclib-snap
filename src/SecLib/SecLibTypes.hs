{-
    A module that exports security types without 
    exposing their constructors, so basically without allowing
    untrusted code to build values of that type.

    Can be imported by untrusted code: Yes
    Type: Trusted
-}

module SecLib.SecLibTypes (
    S, N, A
)
where

import SecLib.Lattice

