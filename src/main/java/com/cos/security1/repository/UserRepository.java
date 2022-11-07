package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
//CRUD 함수를 JpaRepository가 들고 있음.
//JpaRepository를 상속하기 때문에 @Repository라는 어노테이션이 없어도 IoC 대상이 됨.
public interface UserRepository extends JpaRepository<User, Integer> {
    // 메서드 명을 findByUsername으로 해야 select * from user where username= 1?  쿼리를 날린다.
    //마찬가지로 findByEmail()은 select * from user where email= 1?
    //문법에 대해선 Jpa Query Methods 참고.
    public User findByUsername(String username);

}
