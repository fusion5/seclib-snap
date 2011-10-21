\documentclass[11pt,oneside,a4paper]{article}

\topmargin -1.5cm      
\oddsidemargin -0.04cm 
\evensidemargin -0.04cm
\textwidth 16.59cm
\textheight 21.94cm 
\parindent 0pt

%   \setlength\oddsidemargin{ 0in}
%   \setlength\evensidemargin{ 0in}
%   \setlength\textwidth{6.3in}

%include polycode.fmt
%include spacing.fmt

%   format a  = "\alpha"


\usepackage{graphicx}
% \usepackage[osf]{mathpazo}
% \linespread{1.05}         

\title{Software Technology Colloquium}
\author{Drago\c s Ioni\c t\v a}

\frenchspacing

\begin{document}

\maketitle

%if mode=code
\begin{code}
{-# LANGUAGE MultiParamTypeClasses  #-}
{-# LANGUAGE FlexibleInstances      #-}
{-# LANGUAGE FlexibleContexts       #-}
{-# LANGUAGE OverloadedStrings      #-}
{-# LANGUAGE ImplicitParams         #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module Documentation where

import SecLib.Sec hiding (unSecType, sec)
import SecLib.SnapSec hiding (writeBS, getRequest)
import SecLib.Lattice (A, S, N)
import DB.Common (Connection, SqlValue)
import DB hiding (User, Post, Entity, getAll)
import Routes -- (Slug, AdmCrtPost)
import Data.Convertible
import Data.ByteString hiding (empty)
import Control.Applicative
import Control.Monad (unless)
import Snap.Types hiding (route)
import Data.IORef
import Controllers
import Controllers.Common hiding (writeBS, sec, getRequest, getAll)
import Text.Blaze.Html5 as Tag 
import Text.Blaze.Html5.Attributes  as Attr hiding (open)
-- import Text.Blaze.Html5.Attributes  as Attr hiding (open)
import qualified Routes as Routes


data File s = MkFile FilePath

-- Bodies for some type signatures:

-- newtype SecIO s a = MkSecIO (IO (Sec s a))

plug secio_sh@(MkSecIO m) = less sl sh `seq` secio_sl
                            where 
                                 (secio_sl) = MkSecIO (do sha <- m
                                                          return (sec sha))
                                 sl = unSecIOType secio_sl
                                 sh = unSecIOType secio_sh
unSecIOType :: SecIO s a -> s   
unSecIOType _ = undefined

readSecIO   = undefined
writeSecIO  = undefined
runSnapSec  = undefined
pwdCheck    = undefined

\end{code}
%endif

\tableofcontents

\pagebreak

\section{Introduction}

    This paper investigates the use of the |SecLib| Haskell 
library \cite{Russo_Hughes} to guarantee confidentiality for web 
applications.
    An experimental |Snap Framework|-based web application has been 
developed specifically for this purpose.
    In the paper, first, parts of the original library \cite{Russo_Hughes} are 
presented, followed by a description of adaptations made to secure the 
|Snap| web server computation type. 
    Finally, the difficulties encountered on the way and practical aspects of 
the solution are explored, with a focus on (the lack of) user friendliness of 
error reporting, which is one of the libray's major problems.

\section{The |SecLib| library}

In this section the basic concepts in |SecLib| are described.
The library was originally developed to guarantee non-interference 
(defined in subsection \ref{Noninterference}) for Haskell programs in general.
Unlike the |Arrow| library that achieves similar goals 
\cite{Li06encodinginformation},
|SecLib| does not support dynamic security levels: all of them
must be statically known during the type checking phase, since the 
analysis relies on Haskell's type system. 
The basic mechanism that provides security for pure 
computations is presented next.

\subsection{Securing pure values}

Possible security levels are represented as Haskell datatypes. 
For example, a basic two-level security scheme might use:
\begin{code}
data H  = H
data L  = L
\end{code}
Given a value of type |a|, it can be assigned a security level |s|
by using a wrapper constructor, |MkSec|, of type |Sec s a|. 
For instance, the value  
    |MkSec 42 :: Sec L Integer|
    \footnote{|a :: t| $\iff$ the value |a| 
        has type |t|} 
    might represent data of `low sensitivity' and the value 
    |MkSec "Password" :: Sec H String|---`high sensitivity' data.

The meaning assigned to different security levels depends on the 
application and allowed information flow 
(detailed in section \ref{seclevel_lattice}).
In this example, the |L| security 
level may correspond to public values (available to program users), and 
|H|---to private values that must not be exposed to users.

To unwrap a secure value, the library provides the |open| function:
\begin{code}
open ::  Sec s a    ->  s  ->  a
open     (MkSec a)      s  =   s `seq` a
\end{code}
To |open| secured values successfully, access to security level type 
constructors (e.g. |H| or |L|) is required. 
If a different value is passed as |s| parameter to |open|, the program will
not be type-correct. 
If |undefined :: H| is passed instead of a proper security type value, the
program will be correctly typed, however |open| will evaluate to |undefined| 
thanks to |seq|'s semantics.

The security of the application
depends on limiting access to critical functions and values defined in 
\textit{trusted} modules (designed to be imported by \textit{untrusted} code). 
While untrusted code may have access to the |H| and |L| types for use in 
type signatures, it should not have access to their constructors 
(nor should it have access to |MkSec|, since pattern
 matching could then be used to extract wrapped values).
To wrap values, |sec| can be used by untrusted code:
\begin{code}
sec ::  a ->  Sec s a
sec     a =   MkSec a
\end{code}
\subsection{Non-interference}
\label{Noninterference}
    The \textit{Non-interference} security policy preserves data confidentiality,
ensuring data (or, indirectly, information about data) from a `high' security 
level does not flow to a `low' security level. 
For example, a list of username and password hashes can be considered 
`high'-security, since typically they should not be exposed to program users.
An indirect confidentiality leak might be, for example created by 
conditional statements 
(assuming |x| and |y| are `low'-security and |passwordList| is `high' security):

\begin{verbatim}
    if length passwordList > 100 then x else y 
\end{verbatim}

     More formally, a program can be regarded as a black box with 
inputs and outputs that are assigned different security levels. 
For example, the password list mentioned above constitutes an
input of `high' security. 
However, a text which is read from the user may be one of `low' security.

     Security levels |a| and |b| are non-interfering
iff running the program using any sequence of inputs of level |a| always 
produces the same output of level |a|, independent of |b|-level inputs. 
An attacker who can manipulate program inputs at level |a| can not acquire 
any information about data on level |b|.
    
    Inputs of level |a| can, however, influence outputs of level |b|: 
this is called information flow.
   
\subsection{Lattice of security levels}
\label{seclevel_lattice}
For a set of security level types, an application using the library needs a 
relation specifying whether non-interference policies are enforced between
its elements (in the example above, this set is $\{L, H\}$).
Information flow is one of the possible models that define security in 
an application \cite{McLean90securitymodels}.
If the relation is a partial order, information from `low' levels
should be able to flow without restriction to `high' levels. 
Information from `high' levels 
should not flow to `low' levels (unless giving up non-interference 
by introducing specific declassification policies). 
To define the non-interference relation, the |Less| type class is used:
\begin{code}
class Less l h where
    less :: l -> h -> ()
\end{code}
For security types |l| and |h| that are instances of |Less| it is possible 
to use either the |up| function that is allowed to `upgrade' data from level 
|l| to level |h|, or to specify a declassification policy from level |h| to 
level |l|.
If no |Less| instance declaration exists for security types |a| and |b| 
(with |a /= b|), then, |a| and |b| are also non-interfering.

Reflexivity and an example instance for the previous values are expressed 
by the following Haskell code:
\begin{code}
instance Less  a  a  where less _ _ = ()
instance Less  L  H  where less _ _ = () 
\end{code}

Figure \ref{fig1} is an additional
example of security levels lattice, with
|L| -- general public, |B| -- bank, |T| -- tax office and
|G| -- government, with arrows representing |Less| instance declarations.

\begin{figure}[h]
    \begin{center}
        \includegraphics[width=50px]{lat1.pdf}
    \end{center}
    \caption{Example lattice with 4 security level types}
    \label{fig1}
\end{figure}

\subsubsection{Trusted/untrusted code}
    On the one hand, the library guarantees non-interference for untrusted code;
on the other, trusted code has no restrictions, which is why the 
functions it exports to 
untrusted code have to be chosen carefully. The trusted code includes
the security library itself, some functions with side-effects that should
be allowed, and external libraries. 
When dealing with side-effects, security is achieved by providing only 
partial access to the |IO| monad.
    Developers should make sure that the libraries they import do not run unsafe, 
impure computations---straight-forward examples of functions that should be disallowed 
are |unsafePerformIO| and |unsafeCoerce| in |System.IO.Unsafe|. 
    If those were allowed, a `high' security level password list stored in a file 
could be read anywhere in the program, or values could be coerced 
from one security level to another.

\subsubsection{Implementation}
Each instance declaration of the from |Less l h| specifies that 
information can flow from security level |l| to level |h|.
This is done using the |up| function, which is available to 
untrusted code:
\begin{code}
up  :: (Less l h) => Sec l a -> Sec h a
up  sec_l@(MkSec a)  =  less sl sh `seq` sec_h
    where   (sec_h)  =  MkSec a 
            sl       =  unSecType sec_l 
            sh       =  unSecType sec_h

unSecType :: Sec s a -> s 
unSecType _ = undefined
\end{code}

The |up| function first evaluates |less sl sh| using |seq|,
statically ensuring that a |Less| instance declaration exists for the 
respective security levels. To extract the level type, |unSecType|
is used.

% It is not possible to define |Less| instances in untrusted code, 
% because the class is not exported.

\subsubsection{Declassification}
    \label{declassification}
    The non-interference property is, actually, too strict. 
Information flow needs to be allowed in some situations 
(such as when writing a login function)---this is called 
\textit{declassification}.
    The application is more secure when declassification policies are 
centralized, since programmers can control its security without having to 
understand application logic and without having to take into account source 
code spread throughout multiple modules. 
    To allow declassification, a type is introduced for declassification 
functions, |Hatch|: 
\begin{code}
type Hatch h l a b = Sec h a -> IO (Maybe (Sec l b))
\end{code}

A declassification function takes as parameter a security value of level |h|, and
performs a computation using it in a |l|-security context, returning a value of 
type |b|. The |IO| type is needed to implement dynamic policies 
\cite{Broberg06flowlocks}, as exemplified 
in section \ref{dynahatch}.

A combinator that defines a declassification function, given a pure function 
is: 
\begin{code}
hatch :: (Less h l) => (a -> b) -> Hatch h l a b
hatch f sa = return (Just (return (f (reveal sa))))
\end{code}
The |reveal| function extracts a value from its secure wrapper without
having access to the |h| security type constructor (this is only allowed
within trusted code). 
The |Maybe| type is required for returning
a |Nothing| value when declassification is not possible.

\subsubsection{Dynamic hatches}
\label{dynahatch}
Hatch combinators that perform dynamic checks can be defined.
By `dynamic' is meant that the program can decide at runtime whether or not a 
declassification policy is allowed. If it is not, the hatch
function returns a |Nothing| value. |ntimes| is an example of such a 
declassification policy combinator:
\begin{code}
ntimes :: Int -> Hatch h l a b -> IO (Hatch h l a b)  
ntimes n f = do     ref <- newIORef n
                    return $ \sa -> do  k <- readIORef ref
                                        if  k <= 0
                                            then  do    return Nothing
                                            else  do    writeIORef ref (k-1)
                                                        f sa 
\end{code}
The |ntimes| combinator takes a parameter |n| specifying the maximum number 
of times the hatch |f| is allowed to be applied, and returns a modified hatch.
When evaluated, |ntimes| creates a new mutable value |ref|
initialized with the number of times the function is still allowed to be 
applied. For each application of the resulting hatch, |ref| is 
decremented. If it reaches |0|, the declassification will fail by returning 
|Nothing|.

\subsection{Implicit Parameters}

\label{implicitParams}
Provided by the \texttt{ImplicitParams} 
extension \cite{Lewis00implicitparameters}, implicit parameters are functional
dependencies that specify parameter bindings denoted syntactically using the 
|?| prefix in type signatures (as in the |binOp''| example function below).
They can be referenced by code within the context in which they are bound.
Implicit parameters must be specified in the type signatures of functions
that use them (similar to class constraints).
Like class constraints, implicit parameters can also be inferred when type 
signatures are not specified.
Let's look at a trivial but illustrative example. Given a function:
\begin{code}
binOp a b c = (a + b) + c
\end{code}
Let's assume that |binOp| needs to be parametrized over
its operator. That could be done by using a higher-order parameter:
\begin{code}
binOp' op a b c = (a `op` b) `op` c
\end{code}
However, with implicit parameters, the function can be parametrized in the 
following way:
\begin{code}
binOp'' :: (?op::a -> b -> a) => a -> b -> b -> a
binOp'' a b c = ?op (?op a b) c
\end{code}
Finally, when applying |binOp''|, first an |?op| value needs to be set:
\begin{code}
testBinOp'' :: (Num a) => a -> a -> a -> a
testBinOp'' = let ?op = (+) in binOp''
\end{code}

Thus, instead of passing additional function parameters, one can simply 
set implicit parameters. This procedure is especially useful when a
program needs configuration parameters within deeply nested functions, 
where a large number of function definitions would need to be changed 
to add those parameters.

An additional reason for using them for |SecLib| is that, in policies, 
as seen in the |ntimes| combinator example, mutable variables are 
sometimes required. 
A declassification policy that fails if called more than |n| 
times requires a mutable variable that counts the number of times the policy 
was called so far. 
If hatches were brought in scope by simply importing them,
they could be instantiated an unlimited number of times, rendering the 
restriction useless. 
Instead, declassification functions are passed as implicit parameters.

\subsection{Computations with side-effects}

While for pure values |IO| access is needed in order to define declassification
functions, for operations with side-effects that communicate with the exterior 
world, additional guarantees are needed.
It is unsafe to let untrusted code access the |IO| monad.
If that was allowed, and the program had to read a password file, one could 
write code that simply read the file and gained access to classified 
information circumventing any restrictions.
Functions that write to or read from the application state can be added to
the existing framework for pure values by defining a |SecIO| monad and a few
functions operating in it that, in essence, allow untrusted code to perform 
a safe subset of operations normally possible in the |IO| monad.
\begin{code}
newtype SecIO s a = MkSecIO (IO (Sec s a))
\end{code}
Example functions that operate in the |SecIO| monad are:
\begin{code}
readSecIO   :: File s'  -> SecIO s (Sec s' String)
writeSecIO  :: File s'  -> String -> SecIO s ()
\end{code}
Here, |File| is a filename type tagged with a security level type:
for all files that are used, a security level needs to be assigned.

The bind operator for |SecIO| ensures that all operations in a
sequence have the same security level. 
Sometimes it might be useful to execute operations of a `high' security level
within a `low' computation. This can be done using the |plug| combinator, that
returns a pure `high' security value:
\begin{code}
plug :: Less l h => SecIO h a -> SecIO l (Sec h a)
\end{code}

\section{Security for web applications}
In this section |SecLib| is adapted to provide security for a web application. 
In the architecture used here, static security guarantees are offered by the 
library for a single HTTP request when building a response; the web server 
treats all requests identically and handles multi-threading.

In this implementation, the session state is stored in an encrypted 
\textit{cookie} (a string stored by the application client, e.g. web browser,
and sent back to the server with each request).

\subsection{Snap web server}
The \texttt{snap-framework} web server library provides a monad named |Snap| 
which enables access to |Request| and |Response| values. 
Depending on the 
|Request|, the application decides which \textit{route} to take using the
|Applicative| and |Alternative| interfaces.
For example, for a specific application URL, a specific route is 
chosen. Routes offer extensibility and modularity of server code.

For each request, depending on the user level present in the client-side cookie 
(which corresponds to a level type), a specific branch is chosen. 
This is done in the |Main| module, which is part of the trusted code. 
Higher security level branches include all routes from lower ones, that are 
upgraded to a higher level using a variant of the |up| combinator described 
above.

\subsubsection{|Snap| interface example}
In the following example, the behaviour of 
the choice operator for response building is demonstrated. Given the following
|Snap| computations, where |writeBS| is a function that appends a |ByteString|
to the |Response| body:
\begin{code}
route1  ::  Snap ()
route1  =   empty

route2  ::  Snap ()
route2  =   writeBS "Hello World"
\end{code}
Whether applying \texttt{route1 <||> route2} or \texttt{route2 <||> route1}, the 
output will still be |"Hello World"|.
Combinators such as |method| exist in the library, where the first parameter 
is an HTTP verb such as |POST|, |GET|, |PUT|, etc. 
The |action| parameter will only be executed if the current request method 
is equal to the one specified as a parameter:
\begin{code}
method :: Method -> Snap a -> Snap a
method m action = do
    req <- getRequest
    unless (rqMethod req == m) empty
    action
\end{code}

\subsection{Experimental |SecLib| web application}
    To look closer at the requirements of securing a web application, 
an example publishing system has been developed specifically for
this paper, in which users can create posts that they can edit.
    Furthermore, there are username and password based accounts for logging in, 
and the possibility for users to edit their own account. 
\textit{Superusers} can also create/update/delete other user accounts.
    The security lattice chosen for the application (Figure \ref{fig3}) contains
$\{A, N, S\}$, where |S| corresponds to superusers (user administrators), |N| 
corresponds to logged in users, and |A| corresponds to anonymous visitors.
For space considerations, descriptions of the type-safe routing system 
and the libraray used to render HTML forms and acquire user input are omitted.

\begin{figure}[h]
    \begin{center}
        \includegraphics[width=50px]{lat2.pdf}
    \end{center}
    \caption{Security levels in the example application}
    \label{fig3}
\end{figure}

The application stores some values persistently. 
The |Post| and |User| entities are represented within Haskell using 
the following datatypes:
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
Although the current implementation uses the \texttt{HDBC-sqlite3} library which
does not offer type safety and is not easily portable, the concept of 
persistence is abstracted by an |Entity| class. Therefore, other approaches
may be used for persistent storage:
\begin{code}
class Entity a s where
    getAll  :: Connection -> SnapSec s [a]
    getOne  :: (Convertible k SqlValue) => k -> Connection -> SnapSec s (Maybe a)
    insert  :: a -> Connection -> SnapSec s Integer
    delete  :: a -> Connection -> SnapSec s Integer
    update  :: a -> Connection -> SnapSec s Integer
\end{code}
|Entity| instances must be provided as part of the trusted
code (which will require \texttt{MultiParamTypeClasses}) defining entity 
behaviour for one or more security levels. In the example application, they
are: 
\begin{code}
instance Entity  User  S 
instance Entity  Post  N
instance Entity  Post  A
\end{code}
For the |Post| entity, two security levels are assigned. Draft posts cannot
be displayed to |A| (anonymous) level users. The definitions for these instances
require special care to prevent non-interference from being violated.

\subsubsection{Trusted/untrusted code}
In figure \ref{fig2} the application directory tree is summarised, explaining the role 
of files and whether they constitute trusted or untrusted code.
\begin{figure}[h]
    \begin{center}
{\small
\begin{verbatim}src/
  Controllers/              Untrusted   Routes in the SnapSec monad
    Common.hs                           Common functions 
    Frontend.hs                         Front-end (for anonymous users)
    Login.hs                            Login/logout routes
    Posts.hs                            Post CRUD actions
    Users.hs                            User CRUD actions
  DB/                       Trusted
    Common.hs                           Common database definitions
    Post.hs                             Post Entity instances
    User.hs                             User Entity instances, various data definitions
  SecLib/                   Trusted
    DeclCombinators.hs                  Declassification combinators
    DeclCombinatorsTypes.hs             Declassification datatypes
    Declassification.hs                 Exports declassification functions and datatypes
    Lattice.hs                          User level definitions
    Sec.hs                              Secure pure values
    SecLib.hs                           Module to be imported by untrusted code
    SecLibTypes.hs                      Exports lattice types
    SnapSec.hs                          Restricted Snap monad
  Controllers.hs            Untrusted   Convenience module to export all routes 
  Forms.hs                  Untrusted   Defines formlets
  Utils.hs                  Untrusted   Utility functions for untrusted code
  DB.hs                     Trusted     Convenience module to export all entities
  Glue.hs                   Trusted     Snap server code
  Main.hs                   Trusted     Main server code, choosing which route to take
  Policies.hs               Trusted     Contains declassification policies
  Routes.hs                 Trusted     Part of the type-safe URLs and routing system
  Routing.hs                Trusted     Part of the type-safe URLs and routing system
  Server.hs                 Trusted     Server configuration code
  UtilsTrusted.hs           Trusted     Utility functions for trusted code
static/                                 Resource files e.g. images, CSS stylesheets
news.db                                 Sqlite database, persistent data storage
lcookie.key                             Cookie encryption private key\end{verbatim}
}
    \end{center}
    \caption{Trusted/untrusted code in the example application}
    \label{fig2}
\end{figure}


\subsubsection{Securing the |Snap| monad---|SnapSec|}
In the same way that |SecIO| provides a restricted version of |IO|, the 
|SnapSec s a| monad definition exposes only some |Snap| functions to untrusted 
code. The server code can then use |runSnapSec| to obtain a |Snap| computation from
a restricted, |SnapSec| one:
\begin{code}
runSnapSec :: SnapSec s a -> Snap (Sec s a)
\end{code}

\subsubsection{Declassification}
To permit declassification within a |SnapSec| computation, the following 
adaptation of the previous |Hatch| type is used:
\begin{code}
type SnapHatch h l a b = Sec h a -> SnapSec l b
\end{code}
Given a value of level |h| and type |a|, the hatch
can downgrade it to a value of type |b| in a computational context of 
level |l|.

\subsubsection{Declassification policies}
\label{declapol}
The declassification policies in the following list have been considered 
specifically for the experimental application. 
Some of them have flaws, which are based on the assumption that 
malicious code can be introduced in any portion of the untrusted code, i.e.
in code belonging to all security levels:
\begin{itemize}

    \item \begin{code}
deUserAccount :: SnapHatch S N (Maybe User) (Maybe User)
\end{code}
    Given a |User| value, it can be
    downgraded to a lower security level, but only if the user id 
    and level correspond to those of the currently logged-in user. 
    The goal is to allow logged-in-users to access their own account 
    information from the database. 
    This policy would cause leaks if used: since the |User| object
    has a |String| field, any |S| (super) level value representable as a 
    |String| could be injected in this field using |fmap| (since secure 
    values implement the |Functor| interface), and downgraded to 
    an |N| (normal) user level.

    \item \begin{code}
displayPost :: SnapHatch S A (Maybe Post) (Maybe Post)
\end{code}
    A |Post| can be downgraded to an |A| (anonymous) level by 
    |displayPost|, unless it is a draft.
    If exported to untrusted code, a leak could be introduced by malicious 
    code consisting of an |S| (super) level query that would retrieve a 
    non-draft post. 
    Then, |fmap| could be used to modify the resulting 
    value's draft status, which would result in a 
    non-draft post with the same content. 
    This draft |Post| value could then be declassified using |displayPost|, 
    and then outputted within |A| (anonymous) level code.

    \item \begin{code}
deUpdMyAccount  ::  (User -> Connection -> SnapSec S Integer)
                ->  (User -> Connection -> SnapSec N (Maybe Integer))
\end{code}
    This is a higher-order declassification function which is not of type
    |Hatch|. 
    Its purpose is to allow an update operation on the currently logged-in user
    account. But what if the first parameter was a different function that 
    does not update but deletes?
    Then, code could be written such that a logged-in user would at the very least 
    be able to delete their own account (which may not be allowed).
    For this reason, such a declassification function was not used in the 
    application: instead, a trusted |N| (normal) level function that performs the
    update has been used.

    \item \begin{code} 
pwdCheck :: SnapHatch S A (Maybe (Login, User)) (Maybe ByteString)
\end{code}
    |pwdCheck| downgrades user information to a lower security level if the 
    login is successful.
    |Login| represents the data that was sent by the user through the login 
    form (containing a plain text password), and |User| represents the 
    database entry that the login is compared against. In the |User| object, 
    the password must be hashed.

    The returned |ByteString| is encrypted using an |S| (super) level 
    private key.
    This is required because lower security levels normally have access to 
    the |Request| (and |Response|) values, which means they can access 
    cookies. Since lower levels (as well as HTTP clients) should not freely 
    access cookie data, encryption is used. This is still susceptible to 
    brute force decryption attacks, however these attacks could be made 
    unfeasible by choosing a strong key. 
    
    Another improvement would be using a 
    different \texttt{iv} (Initialization Vector) for each encryption 
    function application.
\end{itemize}

The solution chosen for the |displayPost| problem was to eliminate the 
policy altogether, and to define a different |Entity| instance for security 
level |A| (anonymous), which filters out drafts from the original result set.

One other problem that should be avoided when defining hatches is 
polymorphism: defining functions that are too general can lead to unforeseen 
exploits.
Therefore, the types of declassification functions must be monomorphic.

\subsubsection{|SnapSec| combinators}
|SnapSec| also implements the |Applicative| and |Alternative| interfaces, 
behaving similarly to |Snap|.
Furthermore, in addition to a number of adapted |Snap| monad combinators 
that allow response manipulation and request handling adapted to work with
the |SnapSec| monad, two more have been introduced as part of the trusted
code, |ifAnonymous| and |ifLevel|, to control program output depending on the
logged-in user level.

\section{Analysis}

In this section, a number of critical remarks and conclusions are presented 
regarding the adaptation of |SecLib| for a web application.

\subsection{Overview}

One of the main advantages the library has is that it can be used with Haskell 
programs, for which a large number of libraries exist. 
It should not typically add any significant overhead at runtime.
Also, it provides programmers an overview of all potential security 
breaches (introduced in a controlled way by declassification hatches, 
explained in section \ref{declassification})
in a centralised module (|Policies|). 
However, there are problems that may turn out to be unsurmountable in 
practical scenarios.

\subsection{|SecLib| problems}

First, `high' security data can be altered to inject other (supposedly 
protected) `high' security information through policies that allow declassification (as in the case of showing draft posts and downgrading |User| values in
section \ref{declapol}). Some of these problems can be circumvented.

Second, the paper's claim---that the library, together with
a restriction on allowable imported modules in untrusted code, can protect 
against code intentionally written to introduce leaks---does not seem realistic,
at least for the security levels and trusted/untrusted code assumptions in the
example application.
    As far as the non-interference relation goes, the assumption that 
potential attackers can only manipulate `low' security inputs does not seem to 
hold if they can edit untrusted source code. Attackers can
indeed alter `high' security inputs using the |fmap| function in that case. 
In the password list example, the application is susceptible to the insertion of additional 
username/password combinations.
    A likely way to reconcile this problem may be to assume that code operating 
with `high' security inputs should be trusted code.

\subsection{|SnapSec| problems}

Client-side cookies contain encrypted values: the user level 
and user id. This is insecure, as it does not account for the possibility of 
a brute-force attack on the cookie to retrieve the server private key.
It does not protect against replay attacks either, where a third party 
intercepts the request and resends it to gain unwarranted access. 

Currently, level |S| (super) users have limitless access to users and 
password hashes.
Perhaps a more secure design would consist of adding a superior, 
|T| (top) level that is allowed to read user passwords and handle login, 
and restrict user list password access for |S| (super) users; furthermore it should not 
be possible to 
assign the |T| (top) level to users. 
This way it would be more difficult to write code that 
leaks the entire user and password list.

Another problem is that, typically, responses sent to clients can
contain scripts. In a sense, scripts are computations with side-effects that 
are executed by the browser, even though in Haskell they are pure values.
It is possible that these scripts breach confidentiality: they could, 
for instance, post classified information to a URL on the web.
This should be solved by restricting the |Snap| |Response| value by
allowing only non-script content to be created by untrusted code. 
The template output library (\texttt{BlazeHTML} was used here) should run in a
secured, restricted monad, too.
Beside scripts, even simple HTML tags may introduce information leaks, 
as in the following example:
\begin{verbatim}
<img src="http://example.com/sink.php?send=classified_information" />
\end{verbatim}
It is obvious why this can be a leak.
For prevention, further restrictions would be needed on 
HTML combinators to disallow external URLs in tags.
Another possible solution is making scripts and other vulnerable functions part 
of the trusted code. In the system presented here, this remains unsolved.

Finally, a combinator such as |ntimes| is not useful in the context of the |SnapSec|
monad: keeping track of the number of requests should be done per-session, rather
than globally. This requires having session functionality, which is
not provided by \verb snap-framework \footnote{Version \verb 0.2  was used}.

Although more work is needed to provide better, real-world 
security, the use of |SecLib| for web security is helpful at least for 
verifying some security properties when writing one's application.


\subsection{Error messages}

Error reporting is one of the major problems |SecLib| has. 
    Since the library bases its checks on Haskell's type system, the error messages 
produced often do not indicate the location for the root of the problem. 
    For unexperienced programmers, this can be discouraging, making |SecLib| a poor 
choice for some scenarios.

\subsubsection{Security level violation}

When a function is applied in an illegal way (for example if the call context
has lower permissions than the function), a type class error message is issued
by the compiler. Let's assume that the function |respondAdminAddUser| is defined
and has the following type:

\begin{code}
respondAdminAddUser :: (Entity User s, Less A s) => SnapSec s ()
\end{code}
The |Less A s| indicates that it can be applied to a context in a user level |s|
that is superior (or equal) to |A| (anonymous) user level. The |Entity User s| class 
constraint requires level |s| to be declared as an instance for the |User| 
type.
\begin{figure}[h]
\begin{verbatim}
../src/Main.hs:36:26:
    No instance for (DB.Entity DB.User N)
      arising from a use of `respondAdminAddUser'
                   at ../src/Main.hs:36:26-44
    Possible fix: add an instance declaration for (DB.Entity DB.User N)
    In the expression: respondAdminAddUser
    In the definition of `lowRoute':
        lowRoute (AdmUpdPost i) = respondAdminAddUser
\end{verbatim}
    \caption{Function of level |S| used in illegal security level context |N|}
    \label{errormessage1}
\end{figure}

In the error message\footnote{GHC 6.12.1 was used} in figure 
\ref{errormessage1}, |respondAdminAddUser| 
is applied in the |Main| module within an |N| (normal) user level context.  
Since the |User| |Entity| instance (required by the function) was declared 
using security type |S| (super), the type checker will require the |User| type 
to be an instance of |N| (normal), as dictated by the context. 

The function is successfuly prevented from being used. Although this is
one of the cases where the error message indicates the source location where
the problem occurs, the type error message is difficult to interpret by 
programmers who are unfamiliar with the implementation details of |SecLib|.

\subsubsection{Implicit parameters}

The error messages for the \texttt{ImplicitParams} extension discussed in 
section \ref{implicitParams}
are difficult to interpret if type signatures specifying the implicit 
parameters are not present. 
When writing code, it may be preferable, especially when the application 
specifications are not fixed, to let as many function types as possible
to be inferred.
In this case, implicit parameters, if used in an un-type-safe way, will cause 
an error to be reported at the source location where the implicit parameter 
was defined. 
If the type of the implicit value at the location where it is used 
differs from the type at its definition location, the latter is assumed to 
be wrong and reported in the type error message. 

As an example, if we define |binOpWrong| in the following way: 
\begin{code}
binOpWrong a b = ?op a b a
testBinOpWrong = let ?op = (+) in binOpWrong
\end{code}

\begin{figure}[h]
    \begin{center}
\begin{verbatim}
    Occurs check: cannot construct the infinite type: a = a -> t
      Expected type: a -> a -> a
      Inferred type: a -> a -> a -> t
    When using functional dependencies to combine
      ?op::a -> a -> a -> t,
        arising from a use of `binOpWrong' at test.hs:788:34-43
      ?op::a -> a -> a,
        arising from a binding for implicit parameter `?op'
                     at test.hs:788:21-29
    In the expression: let ?op = (+) in binOpWrong
\end{verbatim}
    \end{center}
    \caption{Incorrect usage of an implicit parameter-bound function}
    \label{implicitparamerror}
\end{figure}

The reported error message in figure
\ref{implicitparamerror}
only references the |binOpWrong| definition source code location.
This is a problem especially when there are multiple uses of the same 
implicit parameter in different modules: it becomes difficult to determine 
which uses are wrong.
To fix implicit parameter errors, type signatures need to be specified, 
which is usually time consuming.

\subsubsection{Monomorphism restriction}
A different species of errors are the ones introduced by Haskell's
default monomorphism restriction. 
While they can be easily fixed by using 
the |NoMonomorphismRestriction| language directive, they can still cause 
problems if programmers are unaware of it.
For example, the following code (that displays all posts in 
the administration panel), triggers the error in figure \ref{monomorphismRestriction}:
\begin{code}
respondAdminPosts = do
    addPostLink  <- buildLink Routes.AdmCrtPost
    posts        <- withDB getAll
    postsHtml    <- mapM adminListPostToHtml posts
    respondHtmlContents "Add a post" $ do   p (strong "Existing posts:")
                                            case postsHtml of
                                                []  ->  p "No posts added yet!"
                                                xs  ->  table (mconcat xs)
                                            p $ a ! href addPostLink $ "Add a post"
\end{code}
\begin{figure}[h]
    \begin{center}
\begin{verbatim}
../src/Controllers/Posts.hs:76:27:
    No instance for (Entity Post s)
      arising from a use of `getAll'
                   at ../src/Controllers/Posts.hs:76:27-32
    Possible fix: add an instance declaration for (Entity Post s)
    In the first argument of `withDB', namely `getAll'
    In a stmt of a 'do' expression: posts <- withDB getAll

../src/Controllers/Posts.hs:78:4:
    No instance for (SecLib.Lattice.Less A s)
      arising from a use of `respondHtmlContents'
                   at ../src/Controllers/Posts.hs:78:4-35
    Possible fix:
      add an instance declaration for (SecLib.Lattice.Less A s)
    In the first argument of `(\$)', namely
        `respondHtmlContents "Add a post"'
\end{verbatim}
    \end{center}
    \caption{Errors caused by Haskell's default monomorphism 
                restriction setting (trimmed)}
    \label{monomorphismRestriction}
\end{figure}

When applying the two functions (|getAll| to retrieve all |Post| values and
|respondHtmlContents| to customize the |Response| sent to the client),
a known security type is expected rather than the polymorphic |s|. 

However, by using the |NoMonomorphismRestriction| language directive, the 
function will type-check even though |s| cannot be inferred within the
current module.

\subsubsection{Other polymorphism problems}

When functions do not have type signatures, problems can arise from 
programmers assuming that a specific function is polymorphic in its security 
level |s| (i.e. it works for all security levels, or for a subset of them if 
there is a |Less| class constraint present), when in fact it is not.
Tracking down the function that inadvertently introduces the concrete 
security type can be difficult, despite being solvable by specifying type 
signatures. 
Especially problematic are cases where the function programmers mistakingly 
assume to be polymorphic is defined in a different module. 
While that module will pass the type checking phase, the error will be 
reported in another one. 
In other words, the problem is reported in one location, when it needs to be 
fixed in another. 
The solution involves looking for the problematic function across a significant
code-base in one of the remote modules that are imported, and using the |up| 
combinator to allow a more general, polymorphic type.

In other cases, some secure polymorphic functions do not provide type 
information about which |Entity| instance is required. 
Then, the type needs to be specified using a type signature (possibly using the
|ScopedTypeVariables| extension) as in the following example:
\begin{code}
maybePost :: Maybe Post <- withDB $ getOne idPost
\end{code}
Had the type of maybePost been omitted, the compiler would display
the error in figure \ref{err.unspectype}, once more in a possibly different 
module than where the |maybePost| signature must be added.

\begin{figure}[h]
    \begin{center}
\begin{verbatim}
No instance for (DB.Entity a N)
  arising from a use of `respondAdminDelPost'
               at ../src/Main.hs:37:26-46
Possible fix: add an instance declaration for (DB.Entity a N)
In the expression: respondAdminDelPost i
In the definition of `lowRoute':
    lowRoute (AdmDelPost i) = respondAdminDelPost i
\end{verbatim}
    \end{center}
    \caption{Unspecified concrete |Entity| type error message}
    \label{err.unspectype}
\end{figure}


\section{Conclusion}

This paper presented relevant parts of the original |SecLib| library and 
described adaptations needed to use it with the \verb snap-framework  
web server. 
Then, some of its problems are discussed, concluding that 
in terms of software engineering, the library could turn out to be an 
inappropriate choice for large scale projects, as Haskell compilers often 
generate type error messages that require time and experience to understand 
at first.

As a personal impression, during the development of the experimental 
application, I felt that some of the hurdles introduced by the type system were 
disrupting the flow of development and creating additional work in providing 
type signatures for debugging.

\bibliographystyle{plain}
\bibliography{bibliography}
\end{document}
