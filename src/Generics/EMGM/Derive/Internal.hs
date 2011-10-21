{-# LANGUAGE CPP                    #-}
{-# LANGUAGE TemplateHaskell        #-}

-----------------------------------------------------------------------------
-- |
-- Module      :  Generics.EMGM.Derive.Internal
-- Copyright   :  (c) 2008, 2009 Universiteit Utrecht
-- License     :  BSD3
--
-- Maintainer  :  generics@haskell.org
-- Stability   :  experimental
-- Portability :  non-portable
--
-- Summary: Internal module with implementation of deriving code. Other EMGM
-- modules should import this instead of the higher-level Derive modules.
-----------------------------------------------------------------------------

module Generics.EMGM.Derive.Internal (

  derive,
  deriveWith,
  Modifier(..),
  Modifiers,

  deriveMany,
  deriveManyWith,

  deriveMono,
  deriveMonoWith,

  declareConDescrs,
  declareConDescrsWith,

  declareEP,
  declareEPWith,

  declareRepValues,
  declareRepValuesWith,

  declareMonoRep,
  declareMonoRepWith,

  deriveRep,
  deriveRepWith,

  deriveFRep,
  deriveFRepWith,

  deriveBiFRep,
  deriveBiFRepWith,

  deriveCollect,
  deriveEverywhere,
  deriveEverywhere',

  module Generics.EMGM.Common,
  module Generics.EMGM.Functions.Collect,
  module Generics.EMGM.Functions.Everywhere,

) where

-----------------------------------------------------------------------------
-- Imports
-----------------------------------------------------------------------------

import Prelude

import Language.Haskell.TH
import Data.Maybe (catMaybes)

import Generics.EMGM.Derive.Common
import Generics.EMGM.Derive.Functions

-- We ignore these imports for Haddock, because Haddock does not like Template
-- Haskell expressions in many places.
--
-- See http://code.google.com/p/emgm/issues/detail?id=21
--
#ifndef __HADDOCK__
import Generics.EMGM.Derive.ConDescr (mkConDescr)
import Generics.EMGM.Derive.EP (mkEP)
import Generics.EMGM.Derive.Instance
#endif

import Generics.EMGM.Common

import Generics.EMGM.Functions.Collect
import Generics.EMGM.Functions.Everywhere

-----------------------------------------------------------------------------
-- General functions
-----------------------------------------------------------------------------

#ifndef __HADDOCK__

-- | Make the DT and constructor descriptions
declareConDescrsBase :: Modifiers -> Name -> Q (DT, [Dec])
declareConDescrsBase mods typeName = do
  info <- reify typeName
  case info of
    TyConI d ->
      case d of
        DataD    _ name vars cons _ -> mkDT name vars cons
        NewtypeD _ name vars con  _ -> mkDT name vars [con]
        _                             -> err
    _ -> err
  where
    mkDT name vars cons =
     do pairs <- mapM (normalizeCon mods) cons
        let (ncons', cdDecs) = unzip pairs
        return (DT name vars cons ncons', concat . catMaybes $ cdDecs)
    err = reportError $ showString "Unsupported name \""
                      . shows typeName
                      $ "\". Must be data or newtype."

-- | Normalize constructor variants
normalizeCon :: Modifiers -> Con -> Q (NCon, Maybe [Dec])
normalizeCon mods c =
  case c of
    NormalC name args     -> mkNCon name (map snd args)
    RecC name args        -> mkNCon name (map $(sel 2 3) args)
    InfixC argL name argR -> mkNCon name [snd argL, snd argR]
    ForallC _ _ con       ->
      -- It appears that this ForallC may never be reached, because non-Haskell-98
      -- constructors can't be reified according to an error received when trying.
      do (NCon name _ _ _, _) <- normalizeCon mods con
         reportError $ showString "Existential data constructors such as \""
                     . showString (nameBase name)
                     $ "\" are not supported."
  where
    mkNCon name args =
      do let maybeCdMod = lookup (nameBase name) mods
         (cdName, cdDecs) <- mkConDescr maybeCdMod c
         let names = newVarNames args
         return (NCon name cdName args names, cdDecs)

-- | For each element in a list, make a new variable name using the character
-- 'v' (arbitrary) and a number.
newVarNames :: [a] -> [Name]
newVarNames = map newVarName . zipWith const [1..]
  where
    newVarName :: Int -> Name
    newVarName = mkName . (:) 'v' . show

--------------------------------------------------------------------------------

declareEPBase :: Modifiers -> DT -> Q (Name, [Dec])
declareEPBase mods dt = do
  fromName <- newName "from"
  toName <- newName "to"
  return (mkEP mods dt fromName toName)

declareRepFunsBase :: Modifiers -> DT -> Name -> Q (RepFunNames, [Dec])
declareRepFunsBase mods dt ep = do
  (repFunName,     repFunDecs)     <- mkRepFun mods OptRep      dt ep
  (frepFunName,    frepFunDecs)    <- mkRepFun mods OptFRep     dt ep
  (frep2FunName,   frep2FunDecs)   <- mkRepFun mods OptFRep2    dt ep
  (frep3FunName,   frep3FunDecs)   <- mkRepFun mods OptFRep3    dt ep
  (bifrep2FunName, bifrep2FunDecs) <- mkRepFun mods OptBiFRep2  dt ep
  return
    ( RepFunNames repFunName frepFunName frep2FunName frep3FunName bifrep2FunName
    , repFunDecs ++ frepFunDecs ++ frep2FunDecs ++ frep3FunDecs ++ bifrep2FunDecs
    )

deriveRepBase :: DT -> RepFunNames -> Name -> Q [Dec]
deriveRepBase dt funs g =
  mkRepInst OptRep funs g dt

deriveFRepBase :: DT -> RepFunNames -> Name -> Q [Dec]
deriveFRepBase dt funs g = do
  frepInstDec <- mkRepInst OptFRep funs g dt
  frep2InstDec <- mkRepInst OptFRep2 funs g dt
  frep3InstDec <- mkRepInst OptFRep3 funs g dt
  return (frepInstDec ++ frep2InstDec ++ frep3InstDec)

deriveBiFRepBase :: DT -> RepFunNames -> Name -> Q [Dec]
deriveBiFRepBase dt funs g =
  mkRepInst OptBiFRep2 funs g dt

#endif

-----------------------------------------------------------------------------
-- Exported functions
-----------------------------------------------------------------------------

-- | Same as 'derive' except that you can pass a list of name modifications to
-- the deriving mechanism.
--
-- Use @deriveWith@ if:
--
--  (1) You want to use the generated constructor descriptions or
--  embedding-projection pairs /and/ one of your constructors or types is an
--  infix symbol. In other words, if you have a constructor @:*@, you cannot
--  refer to the (invalid) generated name for its description, @con:*@. It
--  appears that GHC has no problem with that name internally, so this is only
--  if you want access to it.
--
--  (2) You want to define your own constructor description. This allows you to
--  give a precise implementation different from the one generated for you.
--
-- For option 1, use 'ChangeTo' as in this example:
--
-- @
--   data U = Int :* Char
--   $(deriveWith [(\":*\", ChangeTo \"Star\")] ''U)
--   x = ... conStar ...
-- @
--
-- For option 2, use 'DefinedAs' as in this example:
--
-- @
--   data V = (:=) { i :: Int, j :: Char }
--   $(deriveWith [(\":=\", DefinedAs \"Equals\")] ''V)
--   conEquals = 'ConDescr' \":=\" 2 [] ('Infix' 4)
-- @
--
-- Using the example for option 2 with "Generics.EMGM.Functions.Show" will print
-- values of @V@ as infix instead of the default record syntax.
--
-- Note that only the first pair with its first field matching the type or
-- constructor name in the 'Modifiers' list will be used. Any other matches will
-- be ignored.
deriveWith :: Modifiers -> Name -> Q [Dec]

#ifndef __HADDOCK__

deriveWith mods typeName = do
  (dt, conDescrDecs) <- declareConDescrsBase mods typeName
  (epName, epDecs) <- declareEPBase mods dt
  (funNames, funDecs) <- declareRepFunsBase mods dt epName

  g <- newName "g"
  repInstDecs <- deriveRepBase dt funNames g

  higherOrderRepInstDecs <-
    case length (tvars dt) of
      1 -> deriveFRepBase dt funNames g
      2 -> deriveBiFRepBase dt funNames g
      _ -> return []

  collectInstDec <- mkRepCollectInst dt
  everywhereInstDec <- mkRepEverywhereInst dt
  everywhereInstDec' <- mkRepEverywhereInst' dt

  return $
    conDescrDecs           ++
    epDecs                 ++
    funDecs                ++
    repInstDecs            ++
    higherOrderRepInstDecs ++
    [collectInstDec
    ,everywhereInstDec
    ,everywhereInstDec'
    ]

#else

deriveWith = undefined

#endif

-- | Derive all appropriate instances for using EMGM with a datatype.
--
-- Here is an example module that shows how to use @derive@:
--
-- >   {-# LANGUAGE TemplateHaskell       #-}
-- >   {-# LANGUAGE MultiParamTypeClasses #-}
-- >   {-# LANGUAGE FlexibleContexts      #-}
-- >   {-# LANGUAGE FlexibleInstances     #-}
-- >   {-# LANGUAGE OverlappingInstances  #-}
-- >   {-# LANGUAGE UndecidableInstances  #-}
--
-- @
--   module Example where
--   import "Generics.EMGM.Derive"
--   data T a = C a 'Int'
-- @
--
-- @
--   $(derive ''T)
-- @
--
-- The Template Haskell @derive@ declaration in the above example generates the
-- following (annotated) code:
--
-- @
--   -- (1) Constructor description declarations
-- @
--
-- @
--   conC :: 'ConDescr'
--   conC = 'ConDescr' \"C\" 2 [] 'Nonfix'
-- @
--
-- @
--   -- (2) Embedding-projection pair declaration
-- @
--
-- @
--   epT :: 'EP' (T a) (a :*: 'Int')
--   epT = 'EP' fromT toT
--     where fromT (C v1 v2) = v1 :*: v2
--           toT (v1 :*: v2) = C v1 v2
-- @
--
-- @
--   -- (3) Representation values
-- @
--
-- @
--   repT :: ('Generic' g, 'Rep' g a, 'Rep' g 'Int') => g (T a)
--   repT = 'rtype' epT ('rcon' conC ('rprod' 'rep' 'rep'))
-- @
--
-- @
--   frepT :: ('Generic' g) => g a1 -> g (T a1)
--   frepT a = 'rtype' epT ('rcon' conC ('rprod' a 'rint'))
-- @
--
-- @
--   frep2T :: ('Generic2' g) => g a1 a2 -> g (T a1) (T a2)
--   frep2T a = 'rtype2' epT epT ('rcon2' conC ('rprod2' a 'rint2'))
-- @
--
-- @
--   frep3T :: ('Generic3' g) => g a1 a2 a3 -> g (T a1) (T a2) (T a3)
--   frep3T a = 'rtype3' epT epT epT ('rcon3' conC ('rprod3' a 'rint3'))
-- @
--
-- @
--   bifrep2T :: ('Generic2' g) => g a1 a2 -> g (T a1) (T a2)
--   bifrep2T a = 'rtype2' epT epT ('rcon2' conC ('rprod2' a 'rint2'))
-- @
--
-- @
--   -- (4) Representation instances
-- @
--
-- @
--   instance ('Generic' g, 'Rep' g a, 'Rep' g 'Int') => 'Rep' g (T a) where
--     'rep' = repT
-- @
--
-- @
--   instance ('Generic' g) => 'FRep' g T where
--     'frep' = frepT
-- @
--
-- @
--   instance ('Generic2' g) => 'FRep2' g T where
--     'frep2' = frep2T
-- @
--
-- @
--   instance ('Generic3' g) => 'FRep3' g T where
--     'frep3' = frep3T
-- @
--
-- @
--   -- In this case, no instances for 'BiFRep2' is generated, because T is not
--   -- a bifunctor type; however, the bifrep2T value is always generated in
--   -- case T is used in a bifunctor type.
-- @
--
-- @
--   -- (5) Generic function-specific instances
-- @
--
-- @
--   instance 'Rep' ('Collect' (T a)) (T a) where
--     'rep' = 'Collect' (\\x -> [x])
-- @
--
-- @
--   instance ('Rep' ('Everywhere' (T a)) a, 'Rep' ('Everywhere' (T a)) 'Int')
--            => 'Rep' ('Everywhere' (T a)) (T a) where
--     'rep' = 'Everywhere' (\\f x ->
--       case x of
--         C v1 v2 -> f (C ('selEverywhere' 'rep' f v1) ('selEverywhere' 'rep' f v2))
-- @
--
-- @
--   instance 'Rep' ('Everywhere'' (T a)) (T a) where
--     'rep' = 'Everywhere'' (\\f x -> f x)
-- @
--
-- Note that all the values are top-level. This allows them to be shared between
-- multiple instances. For example, if you have two mutually recursive functor
-- datatypes, you may need to have each other's derived code in scope.

derive :: Name -> Q [Dec]
derive = deriveWith []

--------------------------------------------------------------------------------

-- | Same as 'deriveWith' for a list of type names. It may be necessary to use
-- @deriveMany@ for a collection of mutually recursive datatypes.
deriveManyWith :: Modifiers -> [Name] -> Q [Dec]
deriveManyWith mods names = do
  decLists <- mapM (deriveWith mods) names
  return (concat decLists)

-- | Same as 'derive' for a list of type names. It may be necessary to use
-- @deriveMany@ for a collection of mutually recursive datatypes.
deriveMany :: [Name] -> Q [Dec]
deriveMany = deriveManyWith []

--------------------------------------------------------------------------------

-- | Same as 'declareConDescrs' except that you can pass a list of name
-- modifications to the deriving mechanism. See 'deriveWith' for an example.
declareConDescrsWith :: Modifiers -> Name -> Q [Dec]

#ifndef __HADDOCK__

declareConDescrsWith mods typeName = do
  (_, conDescrDecs) <- declareConDescrsBase mods typeName
  return conDescrDecs

#else

declareConDescrsWith = undefined

#endif

-- | Generate declarations of 'ConDescr' values for all constructors in a type.
-- See 'derive' for an example.
declareConDescrs :: Name -> Q [Dec]
declareConDescrs = declareConDescrsWith []

--------------------------------------------------------------------------------

-- | Same as 'declareEP' except that you can pass a list of name modifications
-- to the deriving mechanism. See 'deriveWith' for an example.
declareEPWith :: Modifiers -> Name -> Q [Dec]

#ifndef __HADDOCK__

declareEPWith mods typeName = do
  (dt, _) <- declareConDescrsBase mods typeName
  (_, epDecs) <- declareEPBase mods dt
  return epDecs

#else

declareEPWith = undefined

#endif

-- | Generate declarations of 'EP' values for a type. See 'derive' for an
-- example.
declareEP :: Name -> Q [Dec]
declareEP = declareEPWith []

--------------------------------------------------------------------------------

-- | Same as 'declareMonoRep' except that you can pass a list of name
-- modifications to the deriving mechanism. See 'deriveWith' for an example.
declareMonoRepWith :: Modifiers -> Name -> Q [Dec]

#ifndef __HADDOCK__

declareMonoRepWith mods typeName = do
  (dt, _) <- declareConDescrsBase mods typeName
  (ep, _) <- declareEPBase mods dt
  (_, repFunDecs) <- mkRepFun mods OptRep dt ep
  return repFunDecs

#else

declareMonoRepWith = undefined

#endif

-- | Generate the declaration of a monomorphic representation value for a type.
-- This is the value used for 'rep' in an instance of 'Rep'. The difference with
-- 'declareRepValues' is that 'declareRepValues' generates generates all
-- representation values (including 'frep', 'frep2', etc.). See 'derive' for an
-- example.
declareMonoRep :: Name -> Q [Dec]
declareMonoRep = declareMonoRepWith []

--------------------------------------------------------------------------------

-- | Same as 'declareRepValues' except that you can pass a list of name
-- modifications to the deriving mechanism. See 'deriveWith' for an example.
declareRepValuesWith :: Modifiers -> Name -> Q [Dec]

#ifndef __HADDOCK__

declareRepValuesWith mods typeName = do
  (dt, _) <- declareConDescrsBase mods typeName
  (ep, _) <- declareEPBase mods dt
  (_, funDecs) <- declareRepFunsBase mods dt ep
  return funDecs

#else

declareRepValuesWith = undefined

#endif

-- | Generate declarations of all representation values for a type. These
-- functions are used in 'rep', 'frep', ..., 'bifrep2'.
declareRepValues :: Name -> Q [Dec]
declareRepValues = declareRepValuesWith []

--------------------------------------------------------------------------------

-- | Same as 'deriveRep' except that you can pass a list of name modifications
-- to the deriving mechanism. See 'deriveWith' for an example.
deriveRepWith :: Modifiers -> Name -> Q [Dec]

#ifndef __HADDOCK__

deriveRepWith mods typeName = do
  (dt, _) <- declareConDescrsBase mods typeName
  (ep, _) <- declareEPBase mods dt
  (funNames, _) <- declareRepFunsBase mods dt ep
  g <- newName "g"
  repInstDecs <- deriveRepBase dt funNames g
  return repInstDecs

#else

deriveRepWith = undefined

#endif

-- | Generate 'Rep' instance declarations for a type. See 'derive' for an
-- example.
deriveRep :: Name -> Q [Dec]
deriveRep = deriveRepWith []

--------------------------------------------------------------------------------

-- | Same as 'deriveMono' except that you can pass a list of name
-- modifications to the deriving mechanism. See 'deriveWith' for an example.
deriveMonoWith :: Modifiers -> Name -> Q [Dec]

#ifndef __HADDOCK__

deriveMonoWith mods typeName = do
  (dt, conDescrDecs) <- declareConDescrsBase mods typeName
  (epName, epDecs) <- declareEPBase mods dt
  (repFunName, repFunDecs) <- mkRepFun mods OptRep dt epName
  let funNames = RepFunNames repFunName undefined undefined undefined undefined

  g <- newName "g"
  repInstDecs <- deriveRepBase dt funNames g

  collectInstDec <- mkRepCollectInst dt

  return $
    conDescrDecs           ++
    epDecs                 ++
    repFunDecs             ++
    repInstDecs            ++
    [collectInstDec]

#else

deriveMonoWith = undefined

#endif

-- | Same as 'derive' except that only the monomorphic 'Rep' representation
-- value and instance are generated. This is a convenience function that can be
-- used instead of the following declarations:
--
-- @
--   $(declareConDescrs ''T)
--   $(declareEP ''T)
--   $(declareMonoRep ''T)
--   $(deriveRep ''T)
--   $(deriveFRep ''T)
--   $(deriveCollect ''T)
-- @
deriveMono :: Name -> Q [Dec]
deriveMono = deriveMonoWith []

--------------------------------------------------------------------------------


-- | Same as 'deriveFRep' except that you can pass a list of name modifications
-- to the deriving mechanism. See 'deriveWith' for an example.
deriveFRepWith :: Modifiers -> Name -> Q [Dec]

#ifndef __HADDOCK__

deriveFRepWith mods typeName = do
  (dt, _) <- declareConDescrsBase mods typeName
  (epName, _) <- declareEPBase mods dt
  (funNames, _) <- declareRepFunsBase mods dt epName
  g <- newName "g"
  frepInstDecs <- deriveFRepBase dt funNames g
  return frepInstDecs

#else

deriveFRepWith = undefined

#endif

-- | Generate 'FRep', 'FRep2', and 'FRep3' instance declarations for a type. See
-- 'derive' for an example.
deriveFRep :: Name -> Q [Dec]
deriveFRep = deriveFRepWith []

--------------------------------------------------------------------------------

-- | Same as 'deriveBiFRep' except that you can pass a list of name
-- modifications to the deriving mechanism. See 'deriveWith' for an example.
deriveBiFRepWith :: Modifiers -> Name -> Q [Dec]

#ifndef __HADDOCK__

deriveBiFRepWith mods typeName = do
  (dt, _) <- declareConDescrsBase mods typeName
  (epName, _) <- declareEPBase mods dt
  (funNames, _) <- declareRepFunsBase mods dt epName
  g <- newName "g"
  bifrepInstDecs <- deriveBiFRepBase dt funNames g
  return bifrepInstDecs

#else

deriveBiFRepWith = undefined

#endif

-- | Generate 'BiFRep2' instance declarations for a type. See 'derive' for an
-- example.
deriveBiFRep :: Name -> Q [Dec]
deriveBiFRep = deriveBiFRepWith []

--------------------------------------------------------------------------------

-- | Generate a @'Rep' 'Collect' T@ instance declaration for a type @T@. See
-- 'derive' for an example.
deriveCollect :: Name -> Q [Dec]

#ifndef __HADDOCK__

deriveCollect typeName = do
  (dt, _) <- declareConDescrsBase [] typeName
  collectInstDec <- mkRepCollectInst dt
  return [collectInstDec]

#else

deriveCollect = undefined

#endif

--------------------------------------------------------------------------------

-- | Generate a @'Rep' 'Everywhere' T@ instance declaration for a type @T@. See
-- 'derive' for an example.
deriveEverywhere :: Name -> Q [Dec]

#ifndef __HADDOCK__

deriveEverywhere typeName = do
  (dt, _) <- declareConDescrsBase [] typeName
  everywhereInstDec <- mkRepEverywhereInst dt
  return [everywhereInstDec]

#else

deriveEverywhere = undefined

#endif

-- | Generate a @'Rep' 'Everywhere'' T@ instance declaration for a type @T@. See
-- 'derive' for an example.
deriveEverywhere' :: Name -> Q [Dec]

#ifndef __HADDOCK__

deriveEverywhere' typeName = do
  (dt, _) <- declareConDescrsBase [] typeName
  everywhereInstDec' <- mkRepEverywhereInst' dt
  return [everywhereInstDec']

#else

deriveEverywhere' = undefined

#endif


