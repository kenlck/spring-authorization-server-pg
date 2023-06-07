package com.example.authserver.user.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.authserver.user.model.SecurityUser;

public interface UserRepository extends JpaRepository<SecurityUser, Long> {

  SecurityUser findByUsername(String username);
}
