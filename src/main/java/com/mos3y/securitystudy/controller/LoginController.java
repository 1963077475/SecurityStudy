package com.mos3y.securitystudy.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
@Controller
public class LoginController {
    private Logger logger= LoggerFactory.getLogger(LoginController.class);
    @RequestMapping("/")
    public String showHome(){
        String name= SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("当前登录用户:"+name);
        //获取当前线程中的认证对象
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        //保存认证对象(一般用于自定义认证成功保存认证对象)
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //清空认证对象(一般用于自定义登出清空认证对象)
        SecurityContextHolder.clearContext();
        return "home";
    }
    @RequestMapping("/login")
    public String showLogin(){
        return "login";
    }
    @RequestMapping("/admin")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    /**
     * 通过PreAuthorize进行方法调用前的检测 必须拥有ROLe_ADMIN的角色才可以继续访问
     */
    public String printAdmin() {
        return "如果你看见这句话，说明你有ROLE_ADMIN角色";
    }

    @RequestMapping("/user")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_USER')")
    public String printUser() {
        return "如果你看见这句话，说明你有ROLE_USER角色";
    }
}
