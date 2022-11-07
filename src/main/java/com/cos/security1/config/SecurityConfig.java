package com.cos.security1.config;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
//스프링에서는 특정 메서드에 대해 권한 처리를 하는 MethodSecurity 기능을 제공한다.
//WebSecurity와는 별개로 동작함.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true, jsr250Enabled = true)  //secured 어노테이션 활성화(IndexController의 info메서드 참고
                                                    //securedEnabled = true or false : @Secured 애너테이션을 통해 인가처리(SpEL 지원X)
                                                    //prePostEnabled = true or false : @PreAuthorize, @PostAuthorize 애너테이션을 통해 인가 처리
//                                                      (메서드 호출 전후에 권한 확인. SpEL 지원하며 해당 메서드의 리턴 값을 returnObject로 참조해 SpEL을 통해 인가 처리)
                                                    //jsr250Enabled = true of false : @RolesAllowed 애너테이션을 통해 인가 처리(위 두개는 스프링, 이건 자바 표준. SpEL 지원X)
                                                    //모두 기본 값은 false
public class SecurityConfig {

    private final PrincipalOauth2UserService userService;

    @Bean
    public BCryptPasswordEncoder encodePwd(){
            return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                    .csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/user/**").authenticated()
                    .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                    .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                    .anyRequest().permitAll()
                .and()
                    .formLogin()
                    .loginPage("/loginForm")
                    //.usernameParameter("id") // PrincipalDetailsService의 loadByUsername 메서드 참고.
                    //.passwordParameter("pwd")
                    .loginProcessingUrl("/login")
                    .defaultSuccessUrl("/")//login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행.
                .and()
                    .oauth2Login()
                    .loginPage("/loginForm")   //resource owner가 resource server를 통해 로그인 완료하면 이에 대해 후처리가 필요 (userInfoEndPoint, userService)
                                                //1. 코드 받기(인증), 2. 액세스 토큰(권한),
                                                //3. 사용자 프로필 정보 가져와서, 4. 그 정보를 통해 회원가입
                                                // client는 액세스 토큰 + 프로필 정보 한번에 받는다.
                    .userInfoEndpoint()
                    .userService(userService);
        return http.build();
    }
}
