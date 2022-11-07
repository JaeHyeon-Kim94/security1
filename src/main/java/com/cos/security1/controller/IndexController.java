package com.cos.security1.controller;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.security.RolesAllowed;
import java.util.Objects;

@Controller
@RequiredArgsConstructor
public class IndexController {

    private final UserRepository repository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/test/login")
    public @ResponseBody String testLogin(
            Authentication authentication   //DI받음.
    , @AuthenticationPrincipal PrincipalDetails userDetails // @AuthenticationPrincipal을 통해 세션 정보에 접근 가능
    ){//즉, Authentication을 DI받아 user 정보를 가져오거나, @AuthenticationPrincipal을 통해 세션에서 user 정보를 가져올 수 있다.
        //여기서 세션은 서버 세션 안에 존재하는 시큐리티 세션. 시큐리티 세션 안에는 Authentication만 들어갈 수 있으며,
        //Authentication에는 두 개의 타입이 들어갈 수 있음. UserDetails와 OAuth2User.
        System.out.println("/test/login ==========");
        PrincipalDetails details = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication : " + details.getUser());
        System.out.println("userDetails : " + userDetails.getUsername());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public @ResponseBody String testOAuthLogin(
            Authentication authentication   //DI받음.
            , @AuthenticationPrincipal OAuth2User oauth2User
            ){
        System.out.println("/test/login ==========");
        //testLogin처럼 PrinciaplDetails로 다운 캐스팅시 캐스팅 오류 발생. OAuth2User로 캐스팅해야 함.
        OAuth2User details = (OAuth2User) authentication.getPrincipal();
        System.out.println("authentication : " + details.getAttributes());
        System.out.println("oauth2User : " + oauth2User.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping({"", "/"})
    public String index(){
        return "index";
    }

    //OAUth 로그인을 해도, 일반 폼로그인을 해도 PrincipalDetails로 받을 수 있다.
    //PrincipalDetailsService와 PrincipalOauth2UserService에서 loadByUsername, loadUser 메서드를 오버라이드 하지 않아도
    //시큐리티에 의해 호출되는데, 굳이 두 클래스를 생성하여 메서드 오버라이딩을 한 이유중 하나는
    //OAuth2User와 UserDetails를 상속받는 PrincipalDetails를 리턴함(다형성)으로써 효율적으로 메서드를 설계하고 관리할 수 있기 때문.
    @GetMapping("/user")
    public @ResponseBody String user(@AuthenticationPrincipal PrincipalDetails principalDetails){
        System.out.println("PrincipalDetails : " + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }

    //기존에는 시큐리티가 요청을 가로챘으나, SecurityConfig customize 후에는 작동하지 않음.
    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }

    @PostMapping("/join")
    public @ResponseBody String join(User user){
        System.out.println(user);
        user.setRole("ROLE_USER");
//      회원가입은 되지만, 패스워드 암호화가 되지 않았기 때문에 시큐리티로 로그인 불가능.
//      config에 BCryptPasswordEncoder를 bean으로 등록 해두고 injection 받아 사용.
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        repository.save(user);
        return "redirect:/loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }

    @GetMapping("/info1")
    @Secured("ROLE_ADMIN") //securityConfig의 @EnableGlobalMethodSecurity 애너테이션 참고.
    public @ResponseBody String info1(){
        return "info1";
    }

    @GetMapping("/info2")
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    public @ResponseBody String info2(){
        return "info2";
    }

    @GetMapping("/info3")
    @RolesAllowed({"ROLE_ADMIN"})
    public @ResponseBody String info3(){
        return "info3";
    }

}
