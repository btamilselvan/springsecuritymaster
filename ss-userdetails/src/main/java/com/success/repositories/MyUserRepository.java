package com.success.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.success.entities.MyUser;

@Repository
public interface MyUserRepository extends JpaRepository<MyUser, Long> {
  MyUser findByUsername(String username);
}
