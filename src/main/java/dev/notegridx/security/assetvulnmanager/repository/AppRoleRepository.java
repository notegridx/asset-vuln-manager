package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface AppRoleRepository extends JpaRepository<AppRole, Long> {

    Optional<AppRole> findByRoleName(String roleName);

    List<AppRole> findByRoleNameIn(Collection<String> roleNames);

    List<AppRole> findAllByOrderByRoleNameAsc();
}