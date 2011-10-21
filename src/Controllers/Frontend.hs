{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

{- 
    Handlers for the front-end (requests by anonymous, un-logged-in users)

    Type: Untrusted
-}

module Controllers.Frontend where

import Controllers.Common

import Text.Blaze.Html5 as Tag 
import qualified Routes as Routes

-- respondIndex :: (?displayPosts :: Hatch L A [Post] [Post]) => SnapSec A ()
respondIndex = do
    postsSec :: Sec S [Post] <- plug (withDB getAll)
    posts <- ?displayPosts postsSec 
    sq    <- mapM postToPara posts
    respondHtmlContents "Multiblog system" $ do
        p  "Multi-user web publishing system"
        h1 "Latest posts"
        mconcat sq
    where
        postToPara (Post id slug title contents draft idUserAuthor) = do
            rdPostLink <- buildA (Routes.Post id slug) (fromString title)
            return $ p rdPostLink

respondPost idPost = do
    maybePostSec :: Sec S (Maybe Post) <- plug (withDB (getOne idPost))
    maybePost <- ?displayPost maybePostSec -- Hatch
    editLink  <- buildA (Routes.AdmUpdPost idPost) "Edit post"
    l         <- level
    respondHtmlContents "View post" $ do
        case maybePost of 
            Nothing -> p "Error: post not found!"
            Just (Post idPost slug title contents draft idUserAuthor) -> do
                h1 (fromString title)
                p  (fromString contents)
                case l of 
                    Just SuperUser  -> editLink
                    Just Normal     -> editLink
                    Nothing         -> fromString ""

