package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// 시큐리티 설정에서 loginProcessUrl("/login")으로 걸어뒀기 때문에
// login request 올 시 자동으로 UserDetailsService 타입으로 IoC 되어있는 loadUserByUsername 메서드 실행
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository repository;


    //1.
    //앞단에서 input 태그의 name 속성값이 username, password가 아니라 다른 것이라면 loadUserByUsername 메서드에서 못받음.
    //만약 다른 것으로 하고 싶다면 securityconfig에서 usernameparameter 설정해줘야 함.

    //2.
    //이 메서드가 종료될 때 @AuthenticationPrincipal 어노테이션 만들어짐.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println(username);
        User userEntity = repository.findByUsername(username);
        System.out.println(userEntity);
        if(userEntity!=null){
            //이렇게 user를 담은 UserDetails를 상속받는 PrincipalDetails를 return하게 되면
            //Security session에는 Authentication이, Authentication에는 UserDetails 타입의 PrincipalDetails(userEntity)가 담김.
            return new PrincipalDetails(userEntity);
        }
        return null;
    }
}
