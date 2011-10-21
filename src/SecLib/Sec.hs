{- 
    Module containing the Sec module for secure computations without side 
    effects.

    Can be imported by untrusted code: No
    Type: Trusted
-}

module SecLib.Sec where

import SecLib.Lattice

newtype Sec s a = MkSec a

instance Functor (Sec s) where
    fmap h (MkSec x) = MkSec (h x)

instance Monad (Sec s) where
    return x = sec x
    MkSec a >>= k =
        MkSec (let MkSec b = k a in b)

sec :: a -> Sec s a
sec x = MkSec x

open :: Sec s a -> s -> a
open (MkSec a) s = s `seq` a

up :: Less l h 
   => Sec l a 
   -> Sec h a
up sec_s@(MkSec a) = less s s' `seq` sec_s' 
    where (sec_s') = MkSec a 
          s  = unSecType sec_s 
          s' = unSecType sec_s'

-- For trusted code only
reveal :: Sec s a -> a
reveal (MkSec a) = a

-- Internal function, not exported. For type-checking purposes.
unSecType :: Sec s a -> s 
unSecType _ = undefined

