package com.mos3y.securitystudy.service;

import com.mos3y.securitystudy.domain.SysRole;
import com.mos3y.securitystudy.domain.SysUser;
import com.mos3y.securitystudy.domain.SysUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;

@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private SysUserService userService;
    @Autowired
    private SysRoleService roleService;
    @Autowired
    private SysUserRoleService userRoleService;
    /**
     * 登录页面提交的时候会默认调用loadUserByUsername方法 并且传入用户名
     * @param s 用户名
     * @return 返回用户的权限
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        ArrayList<GrantedAuthority> authorities=new ArrayList<GrantedAuthority>();
        SysUser user=userService.selectByName(s);
        //判断用户是否存在
        if(user==null){
            throw new UsernameNotFoundException("用户名不存在");
        }
        //获取用户的权限
        List<SysUserRole> sysUserRoles = userRoleService.listByUserId(user.getId());
        //添加权限
        for (SysUserRole sysUserRole : sysUserRoles) {
            SysRole role=roleService.selectById(sysUserRole.getRoleId());
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }

        return new User(user.getName(),user.getPassword(),authorities);
    }
}
