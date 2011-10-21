{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ImplicitParams             #-}

{-
    Can be imported by untrusted code: No
    Type: Trusted
-}

module Main where

import Control.Applicative
import Snap.Types hiding (route)
import Snap.Util.FileServe

import SecLib.SecLib
import SecLib.Lattice

import qualified DB as DB 

import Server
import Routing
import Routes
import Controllers
import Utils

import Policies

hiRoute (AdmUpdUser i)  = respondAdminUpdUser i
hiRoute (AdmDelUser i)  = respondAdminDelUser i
hiRoute AdmCrtUser      = respondAdminAddUser
hiRoute AdmUsers        = respondAdminUsers
hiRoute x               = up (lowRoute x) 

lowRoute AdmPosts       = respondAdminPosts
lowRoute AdmCrtPost     = respondAdminAddPost
lowRoute (AdmUpdPost i) = respondAdminUpdPost i
lowRoute (AdmDelPost i) = respondAdminDelPost i
lowRoute Logout         = respondLogout
lowRoute MyAccount      = myAccount
lowRoute x              = up (anonRoute x) 

anonRoute Index         = respondIndex
anonRoute (Post i s)    = respondPost i
anonRoute Login         = respondLogin
anonRoute _             = respondLogin

main :: IO ()
main = do
    {-
       Declassification policies are made available to 
       controller handlers. It is important for type 
       annotations to preserve these implicit parameters.
       One way of preserving them is by not using type
       annotations and letting types be inferred.
       If we had to write type annotations, we would
       have to include hatches in type signatures
       like so: (?x :: Hatch a b c d) => a -> b
    -}
    let ?displayPosts   = displayPosts
        ?displayPost    = displayPost
        ?pwdCheck       = pwdCheck
        ?deUserAccount  = deUserAccount
        ?deUpdMyAccount = deUpdMyAccount
    quickServer $   ifTop
                        (runRoute A respondIndex)
                <|> ifAnonymous
                        (runRoute A (gRouteSnapSec anonRoute))
                <|> ifLevel DB.Normal
                        (runRoute N (gRouteSnapSec lowRoute))
                <|> ifLevel DB.SuperUser
                        (runRoute S (gRouteSnapSec hiRoute))
                <|> dir "static" (fileServe "./static/")

