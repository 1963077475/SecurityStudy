package com.mos3y.securitystudy.service;

import com.mos3y.securitystudy.dao.SysUserRoleMapper;
import com.mos3y.securitystudy.domain.SysUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SysUserRoleService {
    @Autowired
    private SysUserRoleMapper userRoleMapper;

    /**
     * 封装mapper层 并且进行逻辑处理
     * @param userId userId
     * @return 返回用户对应的权限
     */
    public List<SysUserRole> listByUserId(Integer userId) {
        return userRoleMapper.listByUserId(userId);
    }
}
