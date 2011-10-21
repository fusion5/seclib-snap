{-# LANGUAGE ScopedTypeVariables #-}

{- 
    We define here the restricted monad in which we are developing
    our untrusted request-handling functions, as well as some utility 
    functions that are more general than what we have in TrustedUtils.

    Can be imported by untrusted code: No
    Type: Trusted
-}

module SecLib.SnapSec where

import qualified Control.Monad.IO.Class as C
import Control.Applicative

import qualified Data.ByteString as B
import Data.ByteString.Char8 (pack)

import qualified Snap.Types as Snap

import SecLib.Lattice
import qualified SecLib.Sec as Sec
import SecLib.Sec hiding (up)

newtype SnapSec s a = MkSnapSec {
    runSnapSec :: Snap.Snap (Sec s a) 
}

instance Functor (SnapSec s) where
    h `fmap` (MkSnapSec io) = MkSnapSec ( do sec <- io
                                             return (fmap h sec) )

instance Monad (SnapSec s) where
    return x = MkSnapSec (return (return x))
    MkSnapSec m >>= k = MkSnapSec $ do 
                            sa <- m
                            let MkSnapSec m' = k (reveal sa)
                            m'

{-
    It is unsecure to make Snapsec a MonadIO instance. 
    Because with IO access you can do anything with 
    side-effects... untrusted code could gain database access 
    and execute statements we would like to disallow.
    Instead, we simply provide a utility function in the SnapSec
    monad that can execute IO statements. This function is only
    used by trusted code, it's not otherwsie exported to untrusted
    code.
-} 
liftIO io = MkSnapSec (fmap sec (C.liftIO io))

-- Run a route using a specified security level (for trusted code only)
runRoute s snapRoute = do
    r <- runSnapSec snapRoute
    return (open r s)

val :: Sec s a -> SnapSec s a
val sa = MkSnapSec (return sa)

plug :: Less sl sh => SnapSec sh a -> SnapSec sl (Sec sh a)
plug secio_sh@(MkSnapSec m) = less sl sh `seq` secio_sl
    where 
        (secio_sl) = MkSnapSec $ do sha <- m
                                    return (sec sha)
        sl = unSnapSecType secio_sl
        sh = unSnapSecType secio_sh

-- Internal function, not exported. For type-checking purposes.
unSnapSecType :: SnapSec s a -> s   
unSnapSecType _ = undefined

getRequest :: SnapSec s Snap.Request
getRequest = MkSnapSec (fmap sec Snap.getRequest)

modifyResponse :: (Snap.Response -> Snap.Response) -> SnapSec s ()
modifyResponse fresp = MkSnapSec (fmap sec (Snap.modifyResponse fresp))

writeLBS str = MkSnapSec (fmap sec (Snap.writeLBS str))
writeBS  str = MkSnapSec (fmap sec (Snap.writeBS  str))

-- If the current request is using method met, 
-- use the handler given as parameter otherwise fail.
method :: Snap.Method -> SnapSec s a -> SnapSec s a
method met (MkSnapSec s) = MkSnapSec (Snap.method met s)

instance Applicative (SnapSec s) where
    pure = return
    MkSnapSec f <*> MkSnapSec x = MkSnapSec $ 
        do  x' :: Sec s a        <- x
            f' :: Sec s (a -> b) <- f
            let f'' :: (a -> b) = reveal f'
            return $ f'' <$> x'

instance Alternative (SnapSec s) where
    empty = MkSnapSec empty
    MkSnapSec a <|> MkSnapSec b = MkSnapSec (a <|> b)

redirect str = MkSnapSec $ fmap sec (Snap.redirect str)

lift :: (Sec s a -> Sec s b) -> (SnapSec s a -> SnapSec s b)
lift f (MkSnapSec snap) = MkSnapSec $ 
    do  sec <- snap
        return (f sec)

up :: Less s s' => SnapSec s a -> SnapSec s' a
up (MkSnapSec sec_lo) = MkSnapSec (fmap Sec.up sec_lo)

route s snapRoute = do
    r <- runSnapSec snapRoute
    return (open r s)

-- Perhaps it would have been more elegant to include these in another module, 
-- especially if we had more secured files...

cookiePKey :: SnapSec S B.ByteString
cookiePKey = MkSnapSec cookiePKeySnap

cookiePKeySnap :: Snap.Snap (Sec S B.ByteString)
cookiePKeySnap = (sec . pack) <$> C.liftIO (readFile "./lcookie.key")

