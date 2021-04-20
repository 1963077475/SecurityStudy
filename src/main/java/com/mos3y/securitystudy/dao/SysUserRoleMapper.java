package com.mos3y.securitystudy.dao;

import com.mos3y.securitystudy.domain.SysUserRole;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface SysUserRoleMapper {
    /**
     * 通过用户的id查询出用户ID对应的权限Id
     * @param userId 用户Id
     * @return 返回用户对应的权限ID
     */
    @Select("select * from sys_user_role where user_id=#{userId}")
    List<SysUserRole> listByUserId(Integer userId);
}
