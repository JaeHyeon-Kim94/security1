package com.cos.security1.config.auth.provider;

import lombok.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;

@Getter
public class OAuth2UserAttributes {

    @Getter(AccessLevel.NONE)
    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    private String userId;

    private String password;
    private String email;
    private String userName;
    private String provider;

    private OAuth2AccessToken accessToken;
    private String accessToekenValue;
    private String accessTokenType;

    Map<String, Object> attributes;



    @Builder
    public OAuth2UserAttributes(String userId, String password, String email, String userName, String provider, OAuth2AccessToken accessToken, String accessToekenValue, String accessTokenType, Map<String, Object> attributes) {
        this.userId = userId;
        this.password = password;
        this.email = email;
        this.userName = userName;
        this.provider = provider;
        this.accessToken = accessToken;
        this.accessToekenValue = accessToekenValue;
        this.accessTokenType = accessTokenType;
        this.attributes = attributes;
    }

    public static OAuth2UserAttributes of(String provider, OAuth2AccessToken token, Map<String, Object> attributes){
        if("google".equals(provider)){
            return ofGoogle(provider, token, attributes);
        }

        if("naver".equals(provider)){
            return ofNaver(provider, token, attributes);
        }

        if("spotify".equals(provider)){
            return ofSpotify(provider, token, attributes);
        }
        if("kakao".equals(provider)){
            return ofKakao(provider, token, attributes);
        }

        return null;
    }

    private static OAuth2UserAttributes ofKakao(String provider, OAuth2AccessToken token, Map<String, Object> attributes) {
        String userId = String.valueOf(attributes.get("id"));
        String email = (String) ((Map<String, Object>) attributes.get("kakao_account")).get("email");

        return OAuth2UserAttributes.builder()
                .userId(userId)
                .password(randomBCryptedRandomPassword())
                .email(email)
                .accessToekenValue(token.getTokenValue())
                .accessTokenType(token.getTokenType().getValue())
                .provider(provider)
                .userName(provider + "_" + userId)
                .build();
    }

    private static OAuth2UserAttributes ofSpotify(String provider, OAuth2AccessToken token, Map<String, Object> attributes) {
        String userId = String.valueOf(attributes.get("id"));

        return OAuth2UserAttributes.builder()
                .userId(userId)
                .password(randomBCryptedRandomPassword())
                .email((String) attributes.get("email"))
                .accessToekenValue(token.getTokenValue())
                .accessTokenType(token.getTokenType().getValue())
                .provider(provider)
                .userName(provider + "_" + userId)
                .build();
    }

    private static OAuth2UserAttributes ofNaver(String provider, OAuth2AccessToken token, Map<String, Object> attributes) {
        Map<String, Object> ResponseAttributes = (Map<String, Object>) attributes.get("response");
        String userId = (String) ResponseAttributes.get("id");

        return OAuth2UserAttributes.builder()
                .userId(userId)
                .password(randomBCryptedRandomPassword())
                .email((String) ResponseAttributes.get("email"))
                .accessToekenValue(token.getTokenValue())
                .accessTokenType(token.getTokenType().getValue())
                .provider(provider)
                .userName(provider + "_" + userId)
                .build();
    }

    private static OAuth2UserAttributes ofGoogle(String provider, OAuth2AccessToken token, Map<String, Object> attributes) {
        String userId = (String) attributes.get("sub");

        return OAuth2UserAttributes.builder()
                .userId(userId)
                .password(randomBCryptedRandomPassword())
                .email((String) attributes.get("email"))
                .accessToekenValue(token.getTokenValue())
                .accessTokenType(token.getTokenType().getValue())
                .provider(provider)
                .userName(provider + "_" + userId)
                .build();
    }

    private static String randomBCryptedRandomPassword(){
        SecureRandom random = null;
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        StringBuilder sb = new StringBuilder();
        for(int i=0; i<1 ; i++, sb.append(random.nextInt()));
        String password = sb.toString();
        return password = encoder.encode(password);
    }
}
