package com.sharfine.springsecurity.conf;

import com.sharfine.springsecurity.database.model.SysPermission;
import com.sharfine.springsecurity.database.model.SysRole;
import com.sharfine.springsecurity.service.SysPermissionService;
import com.sharfine.springsecurity.service.SysRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {
    @Autowired
    private SysRoleService roleService;
    @Autowired
    private SysPermissionService permissionService;

    @Override
    public boolean hasPermission(Authentication authentication, Object o, Object o1) {
        // 获得loadUserByUsername()方法的结果
        User user = (User) authentication.getPrincipal();
        // 获得loadUserByUsername()中注入的角色
        Collection<GrantedAuthority> grantedAuthorities = user.getAuthorities();
        // 遍历用户所有角色
        for (GrantedAuthority grantedAuthority :
                grantedAuthorities) {

            String roleName = grantedAuthority.getAuthority();
            Integer roleId = roleService.selectByName(roleName).getId();
            // 得到角色所有的权限
            List<SysPermission> sysPermissions = permissionService.listByRoleId(roleId);
            for (SysPermission sysPermission :
                    sysPermissions) {
                // 获取权限集
                List<String> permissions = sysPermission.getPermissions();
                // 如果访问的Url和权限用户符合的话，返回true
                if (o.equals(sysPermission.getUrl()) && permissions.contains(o1)) {
                    return true;
                }
            }
        }

        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable serializable, String s, Object o) {
        return false;
    }
}
