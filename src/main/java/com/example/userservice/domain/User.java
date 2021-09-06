package com.example.userservice.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

// @Entity annotation 쓰면 엔티티 프레임워크 JPA 생성
// @Data 쓰면 lombok 사용
@Entity(name="appuser")
@Data @NoArgsConstructor @AllArgsConstructor
public class User {
    // id 필드를 ID로 정의
    // 자동 생성되도록 정의
    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private String username;
    private String password;
    // Entity relationship 정의
    // fetch type eager로 하면 User를 로드할때 role도 같이 로드한다.
    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<Role> roles = new ArrayList<>();

}
