{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

{- 
    Post editing

    Type: Untrusted
-}

module Controllers.Posts where

import Controllers.Common

import Text.Blaze.Html5             as Tag 
import Text.Blaze.Html5.Attributes  as Attr hiding (open)
import qualified Routes             as Routes

respondAdminAddPost = do
    renderedForm <- withForm (postForm Nothing) defaultFormErrors handleOk
    respondHtmlContents "Administration panel -- Add a post" $ do 
        p (strong "Add a post:")
        renderedForm

handleOk :: Post -> SnapSec N Html
handleOk val = do
    withDB $ insert val
    redirectRoute Routes.AdmPosts
    -- modifyResponseSec $ setResponseStatus 204 "Post added"
    return $ p "Post added"

-- respondAdminUpdPost :: Integer -> SnapSec N ()
respondAdminUpdPost idPost = do
    maybePost <- withDB $ getOne idPost
    renderedForm <- withForm (postForm maybePost) defaultFormErrors handleOk
    respondHtmlContents "Administration panel -- Edit post" $ do
        p (strong "Edit post")
        case maybePost of 
            Nothing  -> p "Error: post not found!"
            Just _   -> renderedForm
    where handleOk val = do withDB $ update val
                            redirectRoute Routes.AdmPosts
                            return $ p "Post updated"

-- respondAdminDelPost :: Integer -> SnapSec N ()
respondAdminDelPost idPost = do
    (maybePost :: Maybe Post) <- withDB $ getOne idPost
    renderForm <- withForm 
        (deleteForm "Are you sure you want to delete this post?") 
        defaultFormErrors 
        (handleDelete maybePost Routes.AdmPosts)
    respondHtmlContents "Administration panel -- Delete post" $ do 
        p (strong "Delete post")
        case maybePost of
            Nothing -> p "Error: post not found!"
            Just _  -> renderForm

-- adminListPostToHtml :: Post -> SnapSec s Html
adminListPostToHtml (Post id slug title contents draft idUserAuthor) = do
    rdPostLink  <- buildA (Routes.Post  id slug) (fromString title)
    updPostLink <- buildA (Routes.AdmUpdPost id) "Update"
    delPostLink <- buildA (Routes.AdmDelPost id) "Delete"
    return $ tr $ do td rdPostLink
                     td $ if draft then "Draft" else "Published"
                     td updPostLink
                     td delPostLink

-- respondAdminPosts :: SnapSec N ()
respondAdminPosts = do
    addPostLink  <- buildLink Routes.AdmCrtPost
    posts        <- withDB getAll
    postsHtml    <- mapM adminListPostToHtml posts
    respondHtmlContents "Add a post" $ do
        p (strong "Existing posts:")
        case postsHtml of
            [] -> p "No posts added yet!"
            xs -> table $ mconcat xs
        p $ a ! href addPostLink $ "Add a post"


