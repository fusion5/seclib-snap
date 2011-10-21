{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE ImplicitParams     #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

{- 
    Module containing controller utilities functions

    Type: Untrusted
-}

module Controllers.Common (
      module Data.String 
    , module Data.Monoid
    , module Control.Monad.IO.Class
    , module Forms
    , module Utils
    , module UtilsTrusted
    , module DB
    , module Snap.Types
    , module SecLib.SecLib
    , module SecLib.SecLibTypes
    , headerDiv
    , pHead
    , respondHtmlBody
    , respondHtmlContents
    , handleDelete
) where

import Data.String (IsString, fromString)
import Data.Monoid (mconcat)

import Snap.Types hiding ( route, modifyResponse, method, writeBS, getRequest
                         , redirect, writeLBS)
import Control.Monad.IO.Class (liftIO)

import SecLib.SecLib 
import SecLib.SecLibTypes

import qualified Routes as Routes
import Forms
import DB
import Utils
import UtilsTrusted

import Text.Blaze.Html5             as Tag
import Text.Blaze.Html5.Attributes  as Attr

pHead titleStr = do
    cssPath <- absolutize ("/static/screen.css")
    return $ Tag.head $ do
        Tag.title titleStr
        Tag.link ! Attr.rel "stylesheet" ! Attr.type_ "text/css" ! Attr.href cssPath

-- Here, we are assuming a layout split 
-- between header and contents: 
respondHtmlContents t cont = do
    header <- headerDiv
    respondHtmlBody t $ do
        header
        (Tag.div ! Attr.id "contents") $ cont

respondHtmlBody t b = do
    head <- pHead t
    respondHtml $ do
        head
        body b

-- Header menu

-- headerDiv :: SnapSec s Html
headerDiv = do
    indexLink  <- buildA Routes.Index       "Homepage"
    postsLink  <- buildA Routes.AdmPosts    "My Posts"
    usersLink  <- buildA Routes.AdmUsers    "Users"
    loginLink  <- buildA Routes.Login       "Login"
    logoutLink <- buildA Routes.Logout      "Logout"
    accLink    <- buildA Routes.MyAccount   "My Account"
    l          <- up level
    return $ (Tag.div ! Attr.id "header") $ do
        ul ! Attr.id "user" $ do
            case l of
                Nothing             ->     li loginLink
                Just Normal         ->     li $ fromString "Normal user rights"
                                        >> li accLink 
                                        >> li logoutLink
                Just SuperUser      ->     li $ fromString "Administrator rights"
                                        >> li accLink 
                                        >> li logoutLink
        ul ! Attr.id "menu" $ do
            case l of
                Nothing             ->     li indexLink
                Just Normal         ->     li indexLink 
                                        >> li postsLink
                Just SuperUser      ->     li indexLink 
                                        >> li postsLink 
                                        >> li usersLink

handleDelete sMaybeObject returnRoute _ = do 
    case sMaybeObject of 
        Nothing  -> modifyResponse $ setResponseStatus 404 "Not found"
        Just obj -> do  withDB $ delete obj
                        return ()
    redirectRoute returnRoute
    return $ p "Object deleted"

