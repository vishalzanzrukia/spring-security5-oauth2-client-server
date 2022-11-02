package com.security.oauth2.server.util;

import java.util.HashMap;

public class Cache {
    static HashMap<String,OAuthRequest> authRequestHashMap = new HashMap<>();

    public static void removeCache(String preAuthCode) {
        if(preAuthCode!=null)
        {
            if(!authRequestHashMap.isEmpty())
            {
                authRequestHashMap.remove(preAuthCode);
            }
        }
    }
    public static void addCache(String preAuthCode,OAuthRequest oAuthRequest)
    {
        authRequestHashMap.put(preAuthCode,oAuthRequest);
    }
    public static OAuthRequest getOauthRequest(String uuid)
    {
        return authRequestHashMap.get(uuid);
    }
}
