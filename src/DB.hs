{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE FlexibleContexts       #-}
{-# LANGUAGE ScopedTypeVariables    #-}
{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE OverloadedStrings      #-}
{-# LANGUAGE TypeSynonymInstances   #-}

{-
    This is the module that untrusted code should import to have access to 
    entity-related datatypes.

    Can be imported by untrusted code: Yes
    Type: Trusted
-}

module DB (
    Entity (..)
  , Post (..)

 -- User datatypes
  , User (..)
  , UserLevel (..)
  , UserPassword (..)
  , UserCookieData (..)
  , Login (..)
  , getByLogin
  , level
  , currentUserId
  , levelSnap
  , cookieEncrypt
  , userCookieData

  , withDB
  , runDB
  , queryDB

    -- Should not be exported (they are here only for shchemata definition 
    -- purposes)
  -- , unsafeWithDBIO
  -- , unsafeResetUsers
  -- , unsafeResetPosts
) where

import DB.Post
import DB.User

import DB.Common

unsafeResetUsers conn = do
    run conn "DROP TABLE IF EXISTS users;" []
    run conn create []
    run conn "INSERT INTO users (level, email, pwdHash) VALUES (?, ?, ?)"
             [ toSql SuperUser
             , toSql ("me@example.com" :: String)
             , toSql ("test"           :: String)
             ]
        where create = "CREATE TABLE users " 
                    ++ "(idUser INTEGER PRIMARY KEY, level INTEGER, email TEXT, pwdHash TEXT)"

unsafeResetPosts conn = do 
    run conn "DROP TABLE IF EXISTS posts;" []
    run conn ( "CREATE TABLE posts ("
            ++ "idPost INTEGER PRIMARY KEY, "
            ++ "postSlug TEXT, postTitle TEXT, "
            ++ "postContents TEXT, "
            ++ "draft INTEGER NOT NULL DEFAULT 1, " 
            ++ "idUserAuthor INTEGER NOT NULL"
            ++ ")") []

unsafeWithDBIO foo = do  
    con <- connectSqlite3 "./news.db"
    r   <- foo con
    commit con
    disconnect con
    return r


