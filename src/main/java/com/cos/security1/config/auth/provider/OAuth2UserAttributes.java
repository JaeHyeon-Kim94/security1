package com.cos.security1.config.auth.provider;

import lombok.Getter;

import java.util.Map;

@Getter
public class OAuth2UserAttributes {

    private String id;
    private String provider;


    Map<String, Object> attributes;


}
