{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE NoMonomorphismRestriction  #-}
{-# LANGUAGE ImplicitParams             #-}

{- 
    User editing, including 'My Account'

    Type: Untrusted
-}

module Controllers.Users where

import Controllers.Common

import Text.Blaze.Html5             as Tag 
import Text.Blaze.Html5.Attributes  as Attr hiding (open)
import qualified Routes             as Routes

-- myAccount :: SnapSec L ()
myAccount = do
    -- idUser <- userId `fmap` getRequestSec
    maybeUserSec <- plug getUser
    maybeUser    <- ?deUserAccount maybeUserSec
    frm          <- withForm (userForm maybeUser False) defaultFormErrors handleOk
    respondHtmlContents "My Account" $ do
        p $ strong "Edit my account"
        frm 
    where handleOk val = do
            -- update which will fail unless the user is logged in
            withDB $ (?deUpdMyAccount update) val
            return $ p "Account updated"

-- Return the currently logged in user by querying the database
getUser :: SnapSec S (Maybe User)
getUser = do
    rq     <- getRequest
    key    <- cookiePKey
    cookie <- lift (userCookieData rq) (return key)
    case cookie of
        Nothing -> return Nothing
        Just (UserCookieData uid lvl) -> withDB $ getOne uid

respondAdminUsers :: SnapSec S ()
respondAdminUsers = do
    addLink   <- buildLink Routes.AdmCrtUser
    users     <- withDB getAll
    usersHtml <- mapM userItem users
    respondHtmlContents "Add a blog user" $ do
        p $ strong "Existing users:"
        case usersHtml of
            [] -> p "No users added yet!"
            xs -> table $ mconcat xs
        p $ do a ! href addLink $ "Add a new user"
    where userItem (User id level email pwdHash) = 
            do  updLink <- buildLink (Routes.AdmUpdUser id)
                delLink <- buildLink (Routes.AdmDelUser id)
                return $ tr $ 
                    do td $ fromString (email ++ " ")
                       td $ fromString ("Level: " ++ show level)
                       td $ (a ! href updLink) "Update"
                       td $ (a ! href delLink) "Delete"

-- respondAdminAddUser :: SnapSec S ()
respondAdminAddUser = do
    renderedForm <- withForm (userForm Nothing True) defaultFormErrors handleOk
    respondHtmlContents "Administration panel -- Add a new user" $ do 
        p (strong "Add a new user:")
        renderedForm
    where handleOk val = do withDB $ insert val
                            redirectRoute Routes.AdmUsers
                            return $ p "User added"

respondAdminDelUser idUser = do
    maybeUser :: Maybe User <- withDB $ getOne idUser
    renderForm <- withForm
        (deleteForm "Are you sure you want to delete this user?") 
        defaultFormErrors 
        (handleDelete maybeUser Routes.AdmUsers)
    respondHtmlContents "Administration panel -- Delete user" $ do 
        p (strong "Delete user")
        case maybeUser of
            Nothing -> p "Error: user not found!"
            Just _  -> renderForm

respondAdminUpdUser idUser = do
    maybeUser    <- withDB $ getOne idUser
    renderedForm <- withForm (userForm maybeUser True) defaultFormErrors handleOk
    respondHtmlContents "Administration panel -- Edit user" $ do
        p (strong "Edit user")
        p "User level changes are effective after the next user login"
        case maybeUser of 
            Nothing  -> p "Error: user not found!"
            Just _   -> renderedForm
    where handleOk val = do withDB $ update val
                            redirectRoute Routes.AdmUsers
                            return $ p "User updated"

