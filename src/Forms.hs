{-# LANGUAGE OverloadedStrings #-}

{-
    Code where forms (i.e. formlets) are defined
    Type: Untrusted
-}

module Forms where

import Control.Applicative
import Control.Applicative.Error
import Control.Monad (forM_)
import Data.Map (toList)
import Data.ByteString.Char8 (unpack)

import Snap.Types hiding (method, getRequest)

import qualified Text.Blaze.Html5 as Tag
import qualified Text.Blaze.Html5.Attributes as Attr

import Text.Blaze.Html5 hiding (map, label, input, textarea, select)
import Text.Blaze.Html5.Formlets
import Data.String (fromString)

import SecLib.SecLib
import DB

nonempty msg field = check field (ensure (not . null) msg)

deleteForm s = label s

postForm post = (\sl ti con dr -> 
                    Post    (maybe 0 idPost post) 
                            sl ti con dr 
                            (maybe 0 idUserAuthor post))
                    <$  label "Post slug name:"
                    <*> nonempty "Please provide a slug" (input (postSlug <$> post))
                    <*  label "Post title:"
                    <*> nonempty "Please provide a post title" (input (postTitle <$> post))
                    <*  label "Post contents:"
                    <*> textarea (Just 10) (Just 80) (postContents <$> post)
                    <*  label "Draft:"
                    <*> checkbox (draft <$> post)

userLevels xs = map f xs
    where f l = (l, fromString (show l))

{-
    The second parameter indicates whether or not to display the select box 
    containing all possible levels
-}
userForm usr True =     User (maybe 0 idUser usr) 
                        <$> levelField      usr       
                        <*> usernameField   usr
                        <*> passwordField   usr

userForm usr False =    User (maybe 0 idUser usr) (maybe Normal userLevel usr) 
                        <$> usernameField usr
                        <*> passwordField usr

levelField usr    =     label "User level:" *> 
                        select  (userLevels [Normal, SuperUser])
                                (userLevel <$> usr)

usernameField usr =     label "Username:" *> 
                        nonempty "Please provide a valid username" (input (email <$> usr))

passwordField usr =     label "Password:" *> 
                        (PlaintextPassword . fromString <$> 
                         nonempty "Please provide a password" (input Nothing))

loginForm login = Login <$  label "Username:"
                        <*> nonempty "Please provide your username " 
                                (input (loginEmail <$> login))
                        <*  label "Password:"
                        <*> nonempty "Please enter your password" 
                                (input Nothing)

-- Helpers

withForm 
    :: Html5Form (SnapSec s) a
    -> (Html -> [String] -> SnapSec s Html) -- error handling
    -> (a -> SnapSec s Html) -- success handler (value a)
    -> SnapSec s Html
withForm frm handleErrors handleOk = 
        (method GET  $ createForm [] frm)
    <|> (method POST $ handlePost)
    where handlePost = do
            rq <- getRequest
            let env = paramsToEnv $ rqParams rq
            let (formResult, frmHtml, _) = runFormState env frm
            v <- formResult
            case v of
                Failure faults -> do
                    -- do we really need to runFormState again here?
                    -- frmHtml <- createForm env frm 
                    handleErrors (wrapForm frmHtml) faults
                Success val -> handleOk val

{-
    type Params = Map ByteString [ByteString] 
    e.g. fromList [("fval[0]",["3"])]
    type Env = [(String, Either String File)]
    attn: we are assuming that xs is non-empty.
-}
paramsToEnv :: Params -> Env
paramsToEnv = map trans . toList
    where trans (s, xs) = (unpack s, Left (unpack $ Prelude.head xs))

createForm :: Env -> Html5Form (SnapSec s) a -> SnapSec s Html
createForm env frm = do
    let (_, frmHtml, _) = runFormState env frm
    return $ wrapForm frmHtml

wrapForm :: Html -> Html
wrapForm frmHtml = 
    Tag.form ! Attr.method "post" $ do
        frmHtml
        Tag.input ! Attr.type_ "submit" ! Attr.value "Submit"

defaultFormErrors form errs = return $ do
    p "Errors:"
    ul ! Attr.class_ "errors" $ forM_ errs (li . fromString)
    form

