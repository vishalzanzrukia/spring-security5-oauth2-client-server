package com.security.oauth2.server.util;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

public class OAuthRequest {
    private String code;
    private String state;
    private String redirectUri;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getRedirectUrl() {
        UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString(getRedirectUri())
                .queryParam(OAuth2ParameterNames.CODE, getCode());
        if (StringUtils.hasText(getState())) {
            uriBuilder.queryParam(OAuth2ParameterNames.STATE, getState());
        }
        return uriBuilder.toUriString();
    }
}
