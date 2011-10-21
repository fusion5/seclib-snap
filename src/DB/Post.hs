{-# LANGUAGE MultiParamTypeClasses  #-}
{-- LANGUAGE FlexibleContexts       #-}
{-- LANGUAGE ScopedTypeVariables    #-}
{-- LANGUAGE FlexibleInstances      #-}
{-- LANGUAGE OverloadedStrings      #-}
{-- LANGUAGE TypeSynonymInstances   #-}

{-
    Module defining Post database functions

    Can be imported by untrusted code: No
    Type: Trusted
-}

module DB.Post where

import DB.Common
import DB.User
import Routes (Slug)
import SecLib.SnapSec (up)

data Post = Post { idPost       :: Integer
                 , postSlug     :: Slug
                 , postTitle    :: String
                 , postContents :: String
                 , draft        :: Bool
                 , idUserAuthor :: Integer
                 }

postFromSqlVals (idPost:slug:title:contents:draft:idUserAuthor:[]) =
    Post (fromSql idPost)
         (fromSql slug) 
         (fromSql title) 
         (fromSql contents)
         (fromSql draft)
         (fromSql idUserAuthor)
postFromSqlVals _ = error "Post conversion error"

-- logged in uers can edit thier own posts:

instance Entity Post N where
    getAll conn = do
        id <- up currentUserId
        postSqlVals <- queryDB conn (
            "SELECT idPost, postSlug, postTitle, postContents, draft, idUserAuthor FROM posts "
         ++ "WHERE idUserAuthor = ?")
            [toSql id]
        return $ (map postFromSqlVals) postSqlVals
    getOne idPost conn = do
        id <- up currentUserId
        postSqlVal  <- queryDB conn (
            "SELECT idPost, postSlug, postTitle, postContents, draft, idUserAuthor FROM posts "
         ++ "WHERE idPost = ? AND idUserAuthor = ?"      )
            [toSql idPost, toSql id]
        case postSqlVal of
            []  -> return $ empty
            x:_ -> return $ pure $ postFromSqlVals x
    insert (Post _ slug title contents draft _) conn = do
        id <- up currentUserId
        runDB conn (
            "INSERT INTO posts (postSlug, postTitle, postContents, draft, idUserAuthor) "
         ++ "VALUES (?, ?, ?, ?, ?)")
            [toSql slug, toSql title, toSql contents, toSql draft, toSql id]
    delete (Post idPost slug title contents draft _) conn = do
        id <- up currentUserId
        runDB conn "DELETE FROM posts WHERE idPost = ? AND idUserAuthor = ?"
            [toSql idPost, toSql id]
    update p@(Post idPost slug title contents draft idUserAuthor) conn = do
        id <- up currentUserId
        runDB conn (
            "UPDATE posts SET postSlug = ?, postTitle = ?, postContents = ?, draft = ? "
         ++ "WHERE idPost = ? AND idUserAuthor = ?")
            [toSql slug, toSql title, toSql contents, 
             toSql draft, toSql idPost, toSql id]

-- High-level post editing allows changing post authors, deleting any post, etc.

instance Entity Post S where
    getAll conn = do
        postSqlVals <- queryDB conn
            "SELECT idPost, postSlug, postTitle, postContents, draft, idUserAuthor FROM posts"
            []
        return $ map postFromSqlVals $ postSqlVals
    getOne idPost conn = do
        postSqlVal <- queryDB conn (
            "SELECT idPost, postSlug, postTitle, postContents, draft, idUserAuthor FROM posts "
            ++ "WHERE idPost = ?")
            [toSql idPost]
        case postSqlVal of
            []  -> return $ empty
            x:_ -> return $ pure $ postFromSqlVals x
    insert (Post idPost slug title contents draft idUserAuthor) conn = do
        runDB conn (
            "INSERT INTO posts (postSlug, postTitle, postContents, draft, idUserAuthor) "
            ++ "VALUES (?, ?, ?, ?, ?)")
            [toSql slug, toSql title, toSql contents, toSql draft, toSql idUserAuthor]
    delete (Post idPost slug title contents draft idUserAuthor) conn = do
        runDB conn "DELETE FROM posts WHERE idPost = ?" 
            [toSql idPost]
    update p@(Post idPost slug title contents draft idUserAuthor) conn = do
        runDB conn (
            "UPDATE posts SET postSlug = ?, postTitle = ?, postContents = ?, draft = ? "
            ++ "WHERE idPost = ?")
            [toSql slug, toSql title, toSql contents, toSql draft, toSql idPost]


