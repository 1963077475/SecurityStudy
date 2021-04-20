package com.mos3y.securitystudy.dao;

import com.mos3y.securitystudy.domain.SysUser;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface SysUserMapper {
    /**
     * 根据ID查询出用户的信息
     * @param id 用户ID
     * @return 返回的用户信息
     */
    @Select("select * from sys_user where id =#{id}")
    SysUser selectById(Integer id);

    /**
     * 根据用户名查询出用户的信息
     * @param name 用户名
     * @return 用户的名对应的信息
     */
    @Select("select * from sys_user where name=#{name}")
    SysUser selectByName(String name);
}
