{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE UndecidableInstances #-}

{- 
    Definition of security level data types as well as 
    the class defining the relation between them.

    Can be imported by untrusted code: No
    Type: Trusted
-}

module SecLib.Lattice where

-- Security types

-- Public information (displayed in the browser):
data A = A  -- Anonymous:       no user
data N = N  -- Normal user:     can manage posts
data S = S  -- Super-user:      can manage users

-- Less 

class Less l h where
  less :: l -> h -> ()

instance Less a a where
  less _ _ = ()

instance Less A S where 
  less _ _ = () 

instance Less A N where 
  less _ _ = () 

instance Less N S where 
  less _ _ = () 


