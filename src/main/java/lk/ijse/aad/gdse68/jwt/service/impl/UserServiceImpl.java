package lk.ijse.aad.gdse68.jwt.service.impl;

import lk.ijse.aad.gdse68.jwt.dto.UserDto;
import lk.ijse.aad.gdse68.jwt.entity.User;
import lk.ijse.aad.gdse68.jwt.repository.UserRepository;
import lk.ijse.aad.gdse68.jwt.service.UserService;
import lk.ijse.aad.gdse68.jwt.util.VarList;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;


@Service
public class UserServiceImpl implements UserDetailsService, UserService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ModelMapper modelMapper;
    @Override
    public int saveUser(UserDto userDto) {
        if(userRepository.existsByEmail(userDto.getEmail()))
        {
            return VarList.Not_Acceptable;
        }else {
            BCryptPasswordEncoder passwordEncoder=new BCryptPasswordEncoder();
            userDto.setPassword(passwordEncoder.encode(userDto.getPassword()));
            userDto.setRole("DASH_ADMIN");
            userRepository.save(modelMapper.map(userDto,User.class));
            return VarList.Created;
        }
    }

    @Override
    public UserDto searchUser(String userName) {
        if (userRepository.existsByEmail(userName)) {
            User user=userRepository.findByEmail(userName);
            return modelMapper.map(user,UserDto.class);
        }else {
            return null;
        }
    }
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email);
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), getAuthority(user));
    }
    public UserDto loadUserDetailByUsername(String username) throws UsernameNotFoundException{
        User user=userRepository.findByEmail(username);
        return modelMapper.map(user,UserDto.class);
    }
    private Set<SimpleGrantedAuthority> getAuthority(User user){
        Set<SimpleGrantedAuthority> authorities=new HashSet<>();
        authorities.add(new SimpleGrantedAuthority(user.getRole()));
        return authorities;
    }
}
