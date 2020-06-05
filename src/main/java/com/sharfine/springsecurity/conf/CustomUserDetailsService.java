package com.sharfine.springsecurity.conf;

import com.sharfine.springsecurity.database.model.SysRole;
import com.sharfine.springsecurity.database.model.SysUser;
import com.sharfine.springsecurity.database.model.SysUserRole;
import com.sharfine.springsecurity.service.SysRoleService;
import com.sharfine.springsecurity.service.SysUserRoleService;
import com.sharfine.springsecurity.service.SysUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private SysUserService userService;
    @Autowired
    private SysRoleService roleService;
    @Autowired
    private SysUserRoleService userRoleService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        //数据库查出用户信息
        SysUser user = userService.selectByName(username);

        //判断用户存不存在
        if (user == null) {
            throw new UsernameNotFoundException("用户名不存在");
        }

        //添加权限
        List<SysUserRole> userRoles = userRoleService.listByUserId(user.getId());
        userRoles.forEach(userRole -> {
            SysRole role = roleService.selectById(userRole.getRoleId());
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        //返回的是UserDetails实现类
        return new User(user.getName(), user.getPassword(), authorities);
    }
}
