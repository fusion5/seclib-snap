{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE ImplicitParams             #-}
{-# LANGUAGE NoMonomorphismRestriction  #-}
{-# LANGUAGE ScopedTypeVariables        #-}

{-
    Module containing helper functions used by controllers
    Type: Untrusted
-}

module Utils where

import Control.Applicative 

import Data.String (IsString, fromString)

import Text.Blaze.Html5 as H hiding (map)
import qualified Text.Blaze.Html5.Attributes as Attr
import Text.Blaze.Renderer.Utf8 (renderHtml)

import Snap.Types hiding (route, method)

import qualified SecLib.SecLib as S

import Routing
import DB
import UtilsTrusted

respondHtml htm = do
    now <- getHttpNow
    S.modifyResponse $ addHeader "Last-Modified" now
    S.modifyResponse $ addHeader "Content-Type" "text/html"
    S.writeLBS (renderHtml $ html htm)

buildLink a = do
    k <- gLinkSnapSec a
    l <- absolutize k
    return $ l

buildA route caption = do
    lnk <- buildLink route
    return $ a ! Attr.href lnk $ caption

absolutize k = return $ fromString $ k

redirectRoute a = do
    backTo <- buildLink a
    S.redirect backTo

ifLevel lvl route = do
    level <- levelSnap
    if level == Just lvl then route else empty

ifAnonymous route = do
    level <- levelSnap
    if level == Nothing then route else empty

