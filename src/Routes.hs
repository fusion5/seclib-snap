{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TemplateHaskell #-}

{-
    Code where routes are defined (a route represent a possible
    URL request for which we must provide a handler)

    Type: Untrusted
-}

module Routes where

import Generics.Regular.TH
import Generics.Regular.Base 

data Blog = Index 
          | Post        Integer Slug
          | AdmPosts
          | AdmCrtPost
          | AdmUpdPost  Integer
          | AdmDelPost  Integer
          | AdmUsers
          | AdmCrtUser
          | AdmUpdUser  Integer
          | AdmDelUser  Integer
          | Login
          | Logout
          | MyAccount
    deriving Show

type Slug = String

$(deriveAll ''Blog "PFBlog")
type instance PF Blog = PFBlog

