package com.cos.security1.config.oauth;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.auth.provider.OAuth2UserAttributes;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private BCryptPasswordEncoder encoder;

    private final UserRepository repository;

    //resource server로부터 받은 userRequest 데이터에 대한 후처리 되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        //로그인 버튼 클릭 -> 소셜 로그인창 -> 로그인 완료 -> code를 리턴(OAuth-Client 라이브러리) -> Access Token 요청
        //userRequest정보 -> 회원 프로필을 받는게 loadUser 메서드.


        OAuth2User oAuth2User = super.loadUser(userRequest);
        String provider = userRequest.getClientRegistration().getRegistrationId();
        System.out.println("getClientRegistration : " + userRequest.getClientRegistration());
        System.out.println("getAdditionalParametners : " + userRequest.getAdditionalParameters());
        System.out.println("getAccessToken.getScopes : " + userRequest.getAccessToken().getScopes());
        System.out.println("getAccessToken.getTokenType : " + userRequest.getAccessToken().getTokenType().getValue());
        System.out.println("getAccesToken.getTokenValues : " + userRequest.getAccessToken().getTokenValue());
        System.out.println("getUserAttributes : " + oAuth2User.getAttributes());
        OAuth2AccessToken token = userRequest.getAccessToken();
        OAuth2UserAttributes attributes = OAuth2UserAttributes.of(provider, token, oAuth2User.getAttributes());


        String role = "ROLE_USER";

        User userEntity = repository.findByUsername(attributes.getUserName());

        if(userEntity == null){
            userEntity = User.builder()
                    .username(attributes.getUserName())
                    .password(attributes.getPassword())
                    .email(attributes.getEmail())
                    .role(role)
                    .provider(provider)
                    .providerId(attributes.getUserId())
                    .build();
            repository.save(userEntity);
        }

        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
