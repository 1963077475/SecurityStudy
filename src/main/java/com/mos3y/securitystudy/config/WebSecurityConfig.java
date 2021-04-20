package com.mos3y.securitystudy.config;

import com.mos3y.securitystudy.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 1.标识为配置类
 * 2.开启Security服务
 * 3.开启全局Security注解
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //
        //                    anonymous() 允许匿名用户访问
        //                      permitAll() 无条件允许访问
        http.authorizeRequests()
                .anyRequest().authenticated() //配置所有的路径必须经过认证
                .and().formLogin().loginPage("/login") //设置过滤登陆页面 用户的登陆认证是由Spring Security进行处理的，请求路径默认为/login，用户名字段默认为username，密码字段默认为password
                .defaultSuccessUrl("/").permitAll() //设置登陆成功的页面
                .and().logout().permitAll(); //设置登出的页面
        http.csrf().disable(); //关闭CSRF跨域
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**","/js/**"); //设置拦截忽略
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //替换掉默认的userDetailService
        auth.userDetailsService(userDetailsService).passwordEncoder(new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                //密码解密 用户的用户名密码和权限都存在userDetailsService中
                return rawPassword.toString();
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return encodedPassword.equals(rawPassword.toString()); //密码校验
            }
        });


    }
}
