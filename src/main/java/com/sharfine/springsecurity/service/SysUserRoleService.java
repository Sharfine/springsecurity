package com.sharfine.springsecurity.service;

import com.sharfine.springsecurity.database.dao.SysUserRoleMapper;
import com.sharfine.springsecurity.database.model.SysUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SysUserRoleService {
    @Autowired
    private SysUserRoleMapper userRoleMapper;

    public List<SysUserRole> listByUserId(Integer userId) {
        return userRoleMapper.listByUserId(userId);
    }
}

