{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts #-}

{-
    Convenience module containing modules used by other database definitions

    Can be imported by untrusted code: No
    Type: Trusted
-}

module DB.Common (
    module Database.HDBC.Sqlite3
  , module Database.HDBC
  , module Control.Applicative
  , module SecLib.Lattice
  , module Data.Convertible
  , Entity (..)
  , withDB
  , queryDB
  , runDB
) where

import Data.Convertible 

import Database.HDBC.Sqlite3
import Database.HDBC

import Control.Applicative

import SecLib.SecLib
import SecLib.Lattice
import SecLib.SnapSec

{-
    Database entity of type `a' with security level `s':
-}
class Entity a s where
    getAll :: Connection -> SnapSec s [a]
    getOne :: (Convertible k SqlValue)
           => k 
           -> Connection 
           -> SnapSec s (Maybe a)
    insert :: a -> Connection -> SnapSec s Integer
    delete :: a -> Connection -> SnapSec s Integer
    update :: a -> Connection -> SnapSec s Integer

withDB :: (Connection -> SnapSec s a) 
       -> SnapSec s a
withDB fun = do  
    con <- liftIO $ connectSqlite3 "./news.db"
    r   <- fun con
    liftIO $ commit con
    liftIO $ disconnect con
    return r

queryDB conn q vals = 
    liftIO $ quickQuery' conn q vals

runDB conn query vals = 
    liftIO $ run conn query vals

