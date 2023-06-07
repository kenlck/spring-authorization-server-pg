package com.example.authserver.user.model.dto;

import org.springframework.security.core.GrantedAuthority;

public class CustomGrantedAuthority implements GrantedAuthority {

  private String name;

  public CustomGrantedAuthority(String name) {
    this.name = name;
  }

  @Override
  public String getAuthority() {
    return name;
  }

}
