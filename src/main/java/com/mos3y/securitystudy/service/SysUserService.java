package com.mos3y.securitystudy.service;

import com.mos3y.securitystudy.dao.SysUserMapper;
import com.mos3y.securitystudy.domain.SysUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SysUserService {
    @Autowired
    private SysUserMapper userMapper;
    public SysUser selectById(Integer id){
        return userMapper.selectById(id);
    }
    public SysUser selectByName(String name) {
        return userMapper.selectByName(name);
    }
}
