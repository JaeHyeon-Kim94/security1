package com.cos.security1.config.auth;


import com.cos.security1.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

//시큐리티가 login request를 낚아채 로그인을 진행함.
//로그인 진행 완료가 되면 시큐리티가 자신의 session을 만듬. (SecurityContextHolder)
// 세션에 들어갈 수 있는 Object는 타입이 정해져있음. Authentication 타입 객체.
//Authentication 안에 User 정보가 있어야 하는데, User 오브젝트 타입은 UserDetails 혹은 OAuth2User
//다형성 활용하여 PrincipalDetails가 UserDetails와 OAuth2User를 상속받으면
//컨트롤러가 됐든 어디든 유저 정보를 DI 받을때 PrincipalDetails 하나로 받을 수 있음.

//즉, Security Session => Authentication => UserDetails
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user; //콤포지션
    private Map<String, Object> attributes;

    //일반 폼 로그인시 사용하는 생성자
    public PrincipalDetails(User user){
        this.user = user;
    }

    //oauth 로그인시 사용하는 생성자
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    //해당 User의 권한을 return하는 곳.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        //1년동안 로그인을 하지 않았을 때 휴면 계정으로 전환하려면 이곳에 로직 작성.(User에서 loginDate 관리하고 있어야 함)
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return (String) attributes.get("sub");
    }
}
