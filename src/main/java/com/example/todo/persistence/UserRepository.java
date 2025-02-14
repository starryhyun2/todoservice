package com.example.todo.persistence;

import com.example.todo.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, String> {
    UserEntity findByEmail(String email);
    boolean existsByEmail(String email);
    UserEntity findByEmailAndPassword(String email, String password);

}
