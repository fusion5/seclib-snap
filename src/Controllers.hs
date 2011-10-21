{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-
    Convenience module that exports all controllers.
    Type: Untrusted
-}

module Controllers (
        module Controllers.Posts
    ,   module Controllers.Users
    ,   module Controllers.Login
    ,   module Controllers.Frontend
) where

-- import Templates.Common
import Controllers.Posts
import Controllers.Users
import Controllers.Login
import Controllers.Frontend
