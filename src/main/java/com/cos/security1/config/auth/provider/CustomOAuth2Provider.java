package com.cos.security1.config.auth.provider;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

public enum CustomOAuth2Provider {
    KAKAO{
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(registrationId
                    , ClientAuthenticationMethod.CLIENT_SECRET_POST
                    , DEFAULT_LOGIN_REDIRECT_URL);

            builder
                    //.scope("profile_nickname")
                    .authorizationUri("https://kauth.kakao.com/oauth/authorize")
                    .tokenUri("https://kauth.kakao.com/oauth/token")
                    .userInfoUri("https://kapi.kakao.com/v2/user/me")
                    .userNameAttributeName("id")
                    .clientName("kakao");

            return builder;
        }
    },

    NAVER{
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {

            ClientRegistration.Builder builder = getBuilder(
                    registrationId
                    , ClientAuthenticationMethod.CLIENT_SECRET_POST
                    , DEFAULT_LOGIN_REDIRECT_URL);

            builder
                    .authorizationUri("https://nid.naver.com/oauth2.0/authorize")
                    .tokenUri("https://nid.naver.com/oauth2.0/token")
                    .userInfoUri("https://openapi.naver.com/v1/nid/me")
                    .clientName("naver")
                    //구글은 sub, 네이버는 response/id
                    .userNameAttributeName("response");

            return builder;
        }
    },

    SPOTIFY{
        @Override
        public ClientRegistration.Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(
                    registrationId
                    , ClientAuthenticationMethod.CLIENT_SECRET_POST
                    , DEFAULT_LOGIN_REDIRECT_URL);

            builder.scope("user-read-email", "user-read-private")
                    .authorizationUri("https://accounts.spotify.com/authorize")
                    .tokenUri("https://accounts.spotify.com/api/token")
                    .userInfoUri("https://api.spotify.com/v1/me")
                    .clientName("spotify")
                    .userNameAttributeName("id");
            return builder;
        }
    };

    private static final String DEFAULT_LOGIN_REDIRECT_URL = "{baseUrl}/login/oauth2/code/{registrationId}";

    protected final ClientRegistration.Builder getBuilder(
            String registrationId
            , ClientAuthenticationMethod method
            , String redirectUrl){
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);

        return builder.clientAuthenticationMethod(method)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUrl);
    }

    public abstract ClientRegistration.Builder getBuilder(String registrationId);
}
