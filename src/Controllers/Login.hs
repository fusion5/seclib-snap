{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ImplicitParams             #-}
{-# LANGUAGE NoMonomorphismRestriction  #-}

{- 
    Login and logout handlers

    Type: Untrusted
-}

module Controllers.Login where

import Controllers.Common
import Control.Applicative

import Text.Blaze.Html5 as Tag 

import qualified Routes as Routes

respondLogout = do 
    now <- getNow
    modifyResponse $ addCookie (getLogoutCookie now)
    redirectRoute Routes.Index

respondLogin = do
    renderedForm <- withForm (loginForm Nothing) defaultFormErrors handleLogin
    respondHtmlContents "Administration panel -- Add a post" $ do 
        p "Authentication:"
        renderedForm

handleLogin l = do
    now     <- getNow
    hiLogin <- plug (login l)
    mCookie <- ?pwdCheck hiLogin
    case mCookie of 
        Nothing     -> return ()
        Just cookie -> modifyResponse $ addCookie (getLoginCookie now cookie)
    redirectRoute Routes.Index
    return $ p "Login Successful"

login :: Login -> SnapSec S (Maybe (Login, User))
login l = do
    usr <- withDB (getByLogin l)
    return ((\u -> (l, u)) <$> usr)

