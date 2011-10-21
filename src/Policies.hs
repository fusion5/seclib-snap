{-# LANGUAGE OverloadedStrings      #-}
{-# LANGUAGE ScopedTypeVariables    #-}

{-
    Policies module, where we define declassification functions 

    Can be imported by untrusted code: No (or yes, if we don't want to use 
    ImplicitParams). However, if we want to use something similar to the 
    ntimes combinator in the paper, we should only use ImplicitParams, because 
    otherwise we can create a limitless number of hatches.

    All policies exported here are flawed except pwdCheck.
    The rest need to be eliminated from the application because of
    flaws explained in the paper.

    Type: Trusted
-}

module Policies (
    pwdCheck
  , displayPosts
  , displayPost
  , deUserAccount
  , deUpdMyAccount
) where

-- Policies is part of the secure application area.

import Data.String
import qualified Data.ByteString as B

import Crypto.Hash.MD5 (hash)

import SecLib.Declassification
import SecLib.SecLib
import SecLib.Lattice
import SecLib.Sec (reveal)

import DB.Common
import DB

{-
    The displayPosts hatch filters out all draft posts for
    display to anonymous users.
-}
displayPosts :: Hatch S A [Post] [Post]
displayPosts = hatch fun
    where   fun :: [Post] -> [Post]
            fun = filter (not . draft)

{-
    This is the same as for displayPosts, except it is done
    for a single post.
-}
displayPost :: Hatch S A (Maybe Post) (Maybe Post)
displayPost = hatch fun
    where   fun :: Maybe Post -> Maybe Post
            fun Nothing  = Nothing
            fun (Just p) = if draft p then Nothing
                                      else Just p

{-
    Here we downgrade the user data information to a lower security level.
    First we check if the Login is valid. Login represents
    the data that was sent by the user through the login form (containing a 
    plain text password), and User represents the database entry that we compare
    the login against. In the User object, the password must be hashed.

    This is required because lower security levels normally have access to the 
    Request (and Response) datatypes, which means they can access cookies.
    The way we solve this problem is by encrypting the cookie string using a private 
    key of level S (cookiePKeySec). This is still susceptible to brute force decryption
    attacks because we are using the same Initialization Vector throughout the 
    application, however this could be changed. Also, a more powerful key could be
    used.
-}
pwdCheck :: Hatch S A (Maybe (Login, User)) (Maybe B.ByteString)
pwdCheck valS = do  keyS <- plug cookiePKey
                    let key = reveal keyS
                    let val = reveal valS
                    case val of 
                        Nothing -> return Nothing
                        Just (Login email pwd, User id lvl mail pwd') -> 
                            if email == mail && valid pwd pwd'  
                                then return $ Just $ cookieEncrypt (UserCookieData id lvl) key
                                else return Nothing
    where   valid pwd (HashedPassword hp)   = hash (fromString pwd) == hp
            valid _   (PlaintextPassword _) = False

{-
    Given the current user login information and a user, we can return the 
    user at a low security level, but only if the user id and the user level 
    of the currently logged-in user coincide. This is basically to allow
    logged-in users to access their own information.
    Not exported (flawed)
-}
deUserAccount :: Hatch S N (Maybe User) (Maybe User)
deUserAccount usr = do
    rq  <- getRequest
    key <- plug cookiePKey
    let fun Nothing    = Nothing
        fun (Just usr) = 
            case reveal (userCookieData rq key) of
                Nothing     -> Nothing  -- No user currently logged in 
                Just cookie -> Just usr -- Return the currently logged in user
    hatch fun usr

{-
    This is a higher-order 'hatch' which is 
    unlike the others. The goal is to allow updating a user account.
    However, what if the first argument was a different function that 
    does not update but does something else such as delete?
    For this reason this should probably not be a hatch at all and just an 
    N-level function, otherwise a currently logged in user would be able
    to delete their own account (which we might or might not want to allow).
    Not exported (flawed)
-}
deUpdMyAccount :: (User -> Connection -> SnapSec S Integer)
               -> (User -> Connection -> SnapSec N (Maybe Integer))
deUpdMyAccount upd = \user conn -> do
    rq  <- getRequest
    key <- plug cookiePKey
    case reveal (userCookieData rq key) of
        Nothing     -> return Nothing
        Just cookie ->
            if cookieUid   cookie == idUser    user
            && cookieLevel cookie == userLevel user
                then do i <- plug (upd user conn) -- perform the actual update
                        return $ Just $ reveal i
                else return Nothing

