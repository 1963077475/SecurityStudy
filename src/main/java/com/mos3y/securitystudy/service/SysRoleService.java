package com.mos3y.securitystudy.service;

import com.mos3y.securitystudy.dao.SysRoleMapper;
import com.mos3y.securitystudy.domain.SysRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SysRoleService {
    @Autowired
    private SysRoleMapper roleMapper;

    /**
     * 封装mapper层 并且进行逻辑处理
     * @param id
     * @return
     */
    public SysRole selectById(Integer id){
        return roleMapper.selectById(id);
    }

}
