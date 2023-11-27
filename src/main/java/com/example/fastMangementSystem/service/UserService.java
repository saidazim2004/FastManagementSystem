package com.example.fastMangementSystem.service;

import com.example.fastMangementSystem.dto.LoginDto;
import com.example.fastMangementSystem.dto.UserCreateDto;
import com.example.fastMangementSystem.dto.response.JwtResponse;
import com.example.fastMangementSystem.entity.user.UserEntity;
import com.example.fastMangementSystem.entity.user.UserRole;
import com.example.fastMangementSystem.exception.DataAlreadyExists;
import com.example.fastMangementSystem.exception.DataNotFoundException;
import com.example.fastMangementSystem.repository.user.UserRepository;
import com.example.fastMangementSystem.service.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public UserEntity save(UserCreateDto userDto, List<UserRole> roles) {
        Optional<UserEntity> userEntityByPhoneNumber = userRepository.findUserEntityByPhoneNumber(userDto.getPhoneNumber());
        if (userEntityByPhoneNumber.isPresent()){
            throw new DataAlreadyExists("User already had");
        }
        UserEntity userEntity = modelMapper.map(userDto, UserEntity.class);
        userEntity.setRoles(roles);
        userEntity.setPassword(passwordEncoder.encode(userEntity.getPassword()));
        return userRepository.save(userEntity);
    }

    public JwtResponse login(LoginDto login) {
        UserEntity userEntity = userRepository.findUserEntityByPhoneNumber(login.getPhoneNumber())
                .orElseThrow(
                        () -> new DataNotFoundException("user not found")
                );

        if(passwordEncoder.matches(login.getPassword(), userEntity.getPassword())) {
            String accessToken = jwtService.generateAccessToken(userEntity);
            return JwtResponse.builder().accessToken(accessToken).build();
        }
        throw new DataNotFoundException("user not found");
    }
    public Optional<UserEntity> getById(UUID id){
       return Optional.ofNullable(userRepository.findById(id).orElseThrow(
               () -> new DataNotFoundException("user not found")));
    }
    public void deleteById(UUID id){
        userRepository.deleteById(id);
    }



}
