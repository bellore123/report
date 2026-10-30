package com.cybershield.repository;

import com.cybershield.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * UserRepository — database access for User entity.
 * Spring Data JPA generates all SQL automatically.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Used by login — find by username
    Optional<User> findByUsername(String username);

    // Check if email is already taken (during registration)
    boolean existsByEmail(String email);

    // Check if username is already taken
    boolean existsByUsername(String username);
}
