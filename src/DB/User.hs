{-# LANGUAGE ScopedTypeVariables    #-}
{-# LANGUAGE OverloadedStrings      #-}
{-# LANGUAGE MultiParamTypeClasses  #-}

{-
    Module defining User database representation as well as other
    user-related datatypes (cookies and login information).

    Can be imported by untrusted code: No
    Type: Trusted
-}

module DB.User where

import Data.ByteString      (ByteString)
import Data.ByteString.UTF8 (toString)
import Data.String          (fromString)

import DB.Common
import Safe (readMay)

import Data.List (find)

import Crypto.Hash.MD5 (hash)
import qualified Data.ByteString        as B
import qualified Data.ByteString.Lazy   as BL
import Data.ByteString.Base64
import Codec.Crypto.AES
import qualified Snap.Types             as Snap

import qualified SecLib.SnapSec         as S
import SecLib.Sec

-- User information stored in a cookie includes
-- only user id and level
data UserCookieData = UserCookieData
    { cookieUid    :: Integer 
    , cookieLevel  :: UserLevel 
    }

{-
    Information supplied when the user is logging in.
    The password is not hashed on the client side, but rather
    on the server side. If sent through an unsecure channel,
    this information can be intercepted.
-}
data Login = Login 
    { loginEmail    :: String
    , loginPassword :: String 
    }

{-
    This defines how we convert user cookie values to/from ByteStrings
    for storage.
-}
instance Convertible ByteString UserCookieData where
    safeConvert str = case readMay (toString str) of
        Nothing -> Left $ ConvertError (show str) "ByteString" "UserCookieData"
            "Cookie conversion error"
        Just (i, l) -> Right $ UserCookieData i (convert (l :: ByteString))

instance Convertible UserCookieData ByteString where
    safeConvert (UserCookieData i l) = 
        Right $ fromString $ show (i, (convert l) :: ByteString)
--

data UserLevel = Normal 
               | SuperUser
   deriving Eq

instance Show UserLevel where
    show Normal         = "Normal user"
    show SuperUser      = "Administrator"

-- Conversion used for cookies

instance Convertible UserLevel ByteString where
    safeConvert Normal      = Right "1"
    safeConvert SuperUser   = Right "2"

instance Convertible ByteString UserLevel where
    safeConvert "1" = Right Normal
    safeConvert "2" = Right SuperUser
    safeConvert x   = Left $ 
        ConvertError (show x) "String" "UserLevel" "User level conversion error"

instance Convertible UserLevel SqlValue where
    safeConvert Normal          = Right (SqlByteString "1")
    safeConvert SuperUser       = Right (SqlByteString "2")

instance Convertible SqlValue UserLevel where
    safeConvert (SqlByteString "1") = Right Normal 
    safeConvert (SqlByteString "2") = Right SuperUser
    safeConvert x = Left $ 
        ConvertError (show x) "SqlValue" "UserLevel" 
            "User level conversion error"

-- 

data UserPassword = PlaintextPassword ByteString
                  | HashedPassword    ByteString

instance Convertible UserPassword SqlValue where
    safeConvert (PlaintextPassword pp) = Right (SqlByteString (hash pp))
    safeConvert (HashedPassword    pp) = Right (SqlByteString pp)

instance Convertible SqlValue UserPassword where
    safeConvert (SqlByteString hp) = Right (HashedPassword hp)
    safeConvert x = Left $ ConvertError (show x) "SqlValue" "UserPassword"
            "User password conversion error"

-- 

-- User datatype used to reprsent user data in the database.

data User = User { idUser       :: Integer
                 , userLevel    :: UserLevel
                 , email        :: String
                 , pwdHash      :: UserPassword }

e2M = either (const Nothing) Just

userFromSqlVals (idUser:level:email:pwdHash:[]) = 
    User (fromSql idUser) (fromSql level) (fromSql email) (fromSql pwdHash)
userFromSqlVals _ = error "User conversion error"

-- getByLogin :: Login -> Connection -> SnapSec S (Maybe User)
getByLogin (Login email pwd) conn = do
    sqlVal <- queryDB conn
        "SELECT idUser, level, email, pwdHash FROM users WHERE email = ?" 
        [toSql email]   
    case sqlVal of 
        []  -> return empty
        x:_ -> return $ pure $ userFromSqlVals x

instance Entity User S where
    getAll conn = do
        sqlVals :: [[SqlValue]] <- queryDB conn 
            "SELECT idUser, level, email, pwdHash FROM users" []
        return $ (map userFromSqlVals) sqlVals
    getOne idUser conn = do
        sqlVal <- queryDB conn
            "SELECT idUser, level, email, pwdHash FROM users WHERE idUser = ?"
            [toSql idUser]
        case sqlVal of
            []  -> return empty
            x:_ -> return $ pure $ userFromSqlVals x
    insert (User _ level email pwdHash) conn = do
        runDB conn 
            "INSERT INTO users (level, email, pwdHash) VALUES (?, ?, ?)"
            [toSql level, toSql email, toSql pwdHash]
    delete (User idUser _ _ _) conn = do
        runDB conn "DELETE FROM users WHERE idUser = ?" 
            [toSql idUser]
    update u@(User idUser level email pwdHash) conn = do
        runDB conn 
                ("UPDATE users SET level = ?, email = ?, pwdHash = ? "
                ++ "WHERE idUser = ?")
                [toSql level, toSql email, toSql pwdHash, toSql idUser]

-- this is bad, the initialization vector should change every time, 
-- not be fixed like in this implementation. However, the purpose of 
-- this project is just showcasing the library and not actually implementing
-- a full-blown secure web login system.
testIv = "1,];,2%n*@0X-!pX"

cookieDecrypt :: B.ByteString -> B.ByteString -> Maybe UserCookieData
cookieDecrypt key encodedCookie = do
    encryptedCookie <- e2M $ decode encodedCookie
    let cookieStr = crypt CFB key testIv Decrypt $ BL.fromChunks [encryptedCookie]
    cookie          <- e2M $ safeConvert $ B.concat $ BL.toChunks $ cookieStr
    return cookie

cookieEncrypt :: UserCookieData -> B.ByteString -> B.ByteString
cookieEncrypt cookie key = let
    cookieLazyStr  = BL.fromChunks [convert cookie]
    in encode $ B.concat $ BL.toChunks $ crypt CFB key testIv Encrypt cookieLazyStr

-- Retrieving actual cookie data must be a high security operation.
-- There is a SnapSec version as well, to allow determining
-- user level throughout the site for security level A.
{-
userCookieData :: Request                   -- Request
               -> Sec S B.ByteString        -- Private key
               -> Sec S (Maybe UserCookie)  -- Possibly a UserCookie value
-}
userCookieData rq skey = 
    case find login cookies of
            Nothing -> return Nothing
            Just c  -> do key <- skey
                          return $ cookieDecrypt key (Snap.cookieValue c)
    where   cookies = Snap.rqCookies rq
            login cookie = (Snap.cookieName cookie == "level")

level :: S.SnapSec A (Maybe UserLevel)
level = do
    rq     <- S.getRequest
    key    <- S.plug S.cookiePKey
    return $ open (levelH rq key) S

-- Current level in Snap monad, publicly available
levelSnap :: Snap.Snap (Maybe UserLevel)
levelSnap = do
    rq     <- Snap.getRequest
    key    <- S.cookiePKeySnap
    return $ open (levelH rq key) S 

levelH :: Snap.Request -> Sec S B.ByteString -> Sec S (Maybe UserLevel)
levelH rq key = fmap (fmap cookieLevel) (userCookieData rq key)

idUserH rq key = fmap (fmap cookieUid) (userCookieData rq key)

currentUserId :: S.SnapSec A (Maybe Integer)
currentUserId = do
    rq     <- S.getRequest
    key    <- S.plug S.cookiePKey
    return $ open (idUserH rq key) S

{-

Different ideas:

getMyAccount :: SnapSec L (Maybe User)
getMyAccount = undefined

updateMyAccount :: User -> SnapSec L ()
updateMyAccount = undefined

userFromSqlValsL (idUser:level:email:[]) = 
    User (fromSql idUser) (fromSql level) (fromSql email) NullPassword
userFromSqlValsL _ = error "User conversion error"

instance Entity User L where
    getAll conn = error "Operation not allowed"
    getOne idUser conn = do
        sqlVal <- quickQuerySec conn
            "SELECT idUser, level, email FROM users WHERE idUser = ?" 
            [toSql idUser]
        case sqlVal of
            []  -> return empty
            x:_ -> return $ pure $ userFromSqlValsL x
    insert (User _ level email pwdHash) conn = do
        runDbSec conn 
            "INSERT INTO users (level, email, pwdHash) VALUES (?, ?, ?)"
            [toSql level, toSql email, toSql pwdHash]
    delete (User idUser _ _ _) conn = do
        runDbSec conn "DELETE FROM users WHERE idUser = ?" 
            [toSql idUser]
    update (User idUser level email pwdHash) conn = do
        runDbSec conn 
            "UPDATE users SET level = ?, email = ?, pwdHash = ? WHERE idUser = ?"
            [toSql level, toSql email, toSql pwdHash, toSql idUser]
-}
