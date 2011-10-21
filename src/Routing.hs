{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}

{-
    Generic 'library' for handling routing
    Type: Untrusted
-}

module Routing (
    gRoute,
    gLink,
    gRouteSnapSec,  -- handle a route in the SnapSec monad
    gLinkSnapSec,   -- Build a link in the SnapSec monad
    GRouteable
) where

import Data.Char (toLower)

import Generics.Regular 
import Data.List (intersperse)

import Control.Applicative
import Data.ByteString.Char8 (unpack)
import qualified Snap.Types as Snap

import qualified SecLib.SecLib as S

type    RoutePath     = [String]
newtype RouteParser a = MkRPP { unRP :: RoutePath -> [(a, RoutePath)] }

instance Applicative RouteParser where
    pure x = MkRPP $ \_ -> [(x, [])]
    MkRPP p <*> MkRPP q = 
        MkRPP $ \s -> [(f x, zs) | (f, ys) <- p s, (x, zs) <- q ys]

instance Functor RouteParser where 
    fmap f (MkRPP xs) = 
        MkRPP $ \s -> fmap (\(a, b) -> (f a, b)) (xs s)

instance Alternative RouteParser where
    empty = MkRPP $ const []
    (MkRPP ls) <|> (MkRPP rs) = MkRPP $ \s -> ls s <|> rs s
    
{-
    Parses a RoutePath and, if it succeeds, returns a Just value.
    If parsing fails, for example if there is ambiguity or no 
    possible parse, then Nothing is returned.
-}
parseRoute :: (Regular a, GRouteable (PF a)) => RoutePath -> Maybe a
parseRoute = extr . unRP (fmap to routeParser)
    where extr ((a, []):_) = Just a
          extr _ = Nothing

{-
    Takes a function as argument that, given a derived GRouteable
    instance, returns a snap server corresponding to the current
    request, or an error response (second argument) if the route
    cannot be parsed (i.e. it's an invalid request)
-}
gRoute :: (GRouteable (PF a), Regular a) => (a -> Snap.Snap b) -> Snap.Snap b
gRoute takeRoute = do
    rp <- stringToRoutePath . unpack . Snap.rqPathInfo <$> Snap.getRequest
    case parseRoute rp of
        Just p  -> takeRoute p
        Nothing -> empty -- fail


{-
    Return an attribute value to be used as a link.
-}
gLink   :: (GRouteable (PF a), Regular a) 
        => a 
        -> Snap.Snap String
gLink routeVal = do
    return $ concat ("/" : intersperse "/" (gRoutePath routeVal))

gRouteSnapSec :: (GRouteable (PF a), Regular a) 
              => (a -> S.SnapSec s b) 
              -> S.SnapSec s ()
gRouteSnapSec takeRoute = do
    rp <- stringToRoutePath . unpack . Snap.rqPathInfo <$> S.getRequest
    case parseRoute rp of
        Just p  -> do takeRoute p
                      return ()
        Nothing -> empty

gLinkSnapSec routeVal = do
    return $ concat ("/" : intersperse "/" (gRoutePath routeVal))
    
{-
    Given a GRouteable instance, build its path.
-}
gRoutePath :: (Regular a, GRouteable (PF a)) => a -> RoutePath
gRoutePath = routeBuilder . from

class GRouteable f where
    routeParser  :: RouteParser (f a)
    routeBuilder :: f a -> RoutePath

instance GRouteable U where
    routeParser = MkRPP $ \rs -> [(U, rs)]
    routeBuilder _ = []

instance GRouteable (K String) where
    routeParser = MkRPP fun
        where   fun []     = []
                fun (r:rs) = [(K r, rs)]
    routeBuilder (K a) = [a]

instance GRouteable (K Integer) where
    routeParser = MkRPP fun
        where   fun []     = []
                fun (r:rs) = [(K (read r), rs)]
    routeBuilder (K i) = [show i]

{-
Recursion is not supported
instance GRouteable I where
    routeParser (f :: [String]) = I f
-}
    
instance (GRouteable f, GRouteable g) => GRouteable (f :+: g) where
    routeParser = (L <$> routeParser) <|> (R <$> routeParser)
    routeBuilder (L l) = routeBuilder l
    routeBuilder (R r) = routeBuilder r

instance (GRouteable f, GRouteable g) => GRouteable (f :*: g) where
    routeParser = (:*:) <$> routeParser <*> routeParser
    routeBuilder (a :*: b) = routeBuilder a ++ routeBuilder b

instance (GRouteable f) => GRouteable (S s f) where
    routeParser = S <$> routeParser
    routeBuilder (S s) = routeBuilder s

instance (Constructor c, GRouteable f) => GRouteable (C c f) where
    routeParser = C <$ keyword cname <*> routeParser
        where cname = map toLower $ conName $ (undefined :: C c f r)
    routeBuilder (C s) = cname : routeBuilder s
        where cname = map toLower $ conName $ (undefined :: C c f r)

-- Utilities 

keyword :: String -> RouteParser String
keyword k = MkRPP $ \xs -> keyword' k xs
    where keyword' _ [] = []
          keyword' a (x:xs) | x == a    = [(x,xs)]
                            | otherwise = []

stringToRoutePath :: String -> RoutePath
stringToRoutePath "" = []
stringToRoutePath s  = let (l, s') = break isUrlSeparator s
                       in l : case s' of
                          []      -> []
                          (_:s'') -> stringToRoutePath s''

isUrlSeparator :: Char -> Bool
isUrlSeparator = (== '/')

