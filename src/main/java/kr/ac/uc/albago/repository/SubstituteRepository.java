package kr.ac.uc.albago.repository;

import kr.ac.uc.albago.entity.SubstituteEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SubstituteRepository extends JpaRepository<SubstituteEntity, Long> {
    List<SubstituteEntity> findByUser_Email(String email);
}
