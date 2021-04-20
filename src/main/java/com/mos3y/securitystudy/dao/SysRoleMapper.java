package com.mos3y.securitystudy.dao;

import com.mos3y.securitystudy.domain.SysRole;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface SysRoleMapper {
    /**
     * 根据ID查询出角色的权限信息
     * @param id 角色的ID
     * @return 对应角色的权限
     */
    @Select("select * from sys_role where id=#{id}")
    SysRole selectById(Integer id);
}
