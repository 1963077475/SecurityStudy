测试自博客

https://blog.csdn.net/yuanlaijike/article/details/80249235



### 测试流程

1.创建实体类 domain包

SysUser

```java
package com.mos3y.securitystudy.domain;

import org.springframework.web.servlet.config.annotation.InterceptorRegistry;

import java.io.Serializable;

public class SysUser implements Serializable
{
    private static final long serialVersionUID=1L;

    private Integer id;
    private String name;
    private String password;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

```

SysRole

```java
package com.mos3y.securitystudy.domain;

import java.io.Serializable;

public class SysRole implements Serializable
{
    private final long serialVersionUID=1L;
    private Integer id;

    private String name;

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}

```

SysUserRole

```java
package com.mos3y.securitystudy.domain;

import java.io.Serializable;

public class SysUserRole implements Serializable {
    static final long serialVersionUID = 1L;

    private Integer userId;

    private Integer roleId;

    public Integer getUserId() {
        return userId;
    }

    public void setUserId(Integer userId) {
        this.userId = userId;
    }

    public Integer getRoleId() {
        return roleId;
    }

    public void setRoleId(Integer roleId) {
        this.roleId = roleId;
    }
// 省略getter/setter
}

```

2.创建Dao层

SysRoleMapper

```java
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
```

SysUserMapper

```java
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
```

SysUserRoleMapper

```java
@Mapper
public interface SysUserRoleMapper {
    /**
     * 通过用户的id查询出用户ID对应的权限Id
     * @param userId 用户Id
     * @return 返回用户对应的权限ID
     */
    @Select("select * from sys_user_role where user_id=#{userId}")
    List
```

3.编写Service层

SysRoleService

```java
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
```

SysUserRoleService

```java

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
```



SysUserService

```java
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
```

4.controller层

```java
@Controller
public class LoginController {
    private Logger logger= LoggerFactory.getLogger(LoginController.class);
    @RequestMapping("/")
    public String showHome(){
        String name= SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("当前登录用户:"+name);
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
```

5.配置SpringSecurity的配置类

```java

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
                .and().formLogin().loginPage("/login") //设置过滤登陆页面用户的登陆认证是由Spring Security进行处理的，请求路径默认为/login，用户名字段默认为username，密码字段默认为password
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

```

6.配置UserDetailsService的实现类

```java
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
```

### SpringSecurity登录流程

最常用的UsernamePasswordAuthenticationToken

保存了登录用户的基本信息

```java

public class UsernamePasswordAuthenticationFilter extends
		AbstractAuthenticationProcessingFilter {
	public UsernamePasswordAuthenticationFilter() {			//添加登录请求路径和提交方式
		super(new AntPathRequestMatcher("/login", "POST"));
	}
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
        //获取用户和密码 通过obtainUsernama 和obtainPassword方法
		String username = obtainUsername(request);
		String password = obtainPassword(request);
        //构造UsernamePasswordAuthenticationToken对象
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
				username, password);
        //给Detail属性赋值 描述了两个信息 rempteAddress和请求的sessionID
		setDetails(request, authRequest);
        //调用authenicate方法进行校验
		return this.getAuthenticationManager().authenticate(authRequest);
	}
	protected String obtainPassword(HttpServletRequest request) {
		return request.getParameter(passwordParameter);
	}
	protected String obtainUsername(HttpServletRequest request) {
		return request.getParameter(usernameParameter);
	}
	protected void setDetails(HttpServletRequest request,
			UsernamePasswordAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
}
```

#### 具体的校验操作

使用ProvicerManager来进行校验操作

```java

public Authentication authenticate(Authentication authentication)
		throws AuthenticationException {
    //获取传入的Authentication的类型
	Class<? extends Authentication> toTest = authentication.getClass();
	for (AuthenticationProvider provider : getProviders()) {
        //判断是否支持传入的Authentication 如果支持则使用provider进行校验
		if (!provider.supports(toTest)) {
			continue;
		}
		result = provider.authenticate(authentication);
		if (result != null) {
            //将旧的Token的details属性拷贝到新的Token当中来
			copyDetails(authentication, result);
			break;
		}
	}
	if (result == null && parent != null) {
		result = parentResult = parent.authenticate(authentication);
	}
	if (result != null) {
		if (eraseCredentialsAfterAuthentication
				&& (result instanceof CredentialsContainer)) {
			((CredentialsContainer) result).eraseCredentials();
		}
		if (parentResult == null) {//将登陆成功的事件广播出去
			eventPublisher.publishAuthenticationSuccess(result);
		}
		return result;
	}
	throw lastException;
}
```

#### authenticate 认证方法流程

DaoAuthenticationProvider 的authenticate认证方法

```java
public Authentication authenticate(Authentication authentication)
		throws AuthenticationException {
    //首先从authentication中提取出用户名
	String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED"
			: authentication.getName();
    //这个方法会调用我们自己实现的UserDetailsService的实现类中的loadUserByUsername方法 放回的user就是自己的登陆对象
	user = retrieveUser(username,(UsernamePasswordAuthenticationToken) authentication);
    //使用preAuthenticationChecks。check方法检测user的用户状态是否正常 是否被金庸 是否过期
	preAuthenticationChecks.check(user);
    //这个方法是对密码进行比较 在实现类中有相应的代码
	additionalAuthenticationChecks(user,(UsernamePasswordAuthenticationToken) authentication);
    //检查密码是否过期
	postAuthenticationChecks.check(user);
	Object principalToReturn = user;
	if (forcePrincipalAsString) {
		principalToReturn = user.getUsername();
	}
    //最后构建一个全新的UsernamePasswordToken
	return 
        createSuccessAuthentication(principalToReturn, authentication, user);
}

```

登录来自博客https://blog.csdn.net/minkeyto/article/details/104790771/

#### 身份认证流程

`SecurityContextHolder` 存储 `SecurityContext` 对象。

默认是MODE_THREADLOCAL存储在当前的线程中 也可以使用其他的两种存储模式

- MODE_INHERITABLETHREADLOCAL：`SecurityContext` 存储在线程中，但子线程可以获取到父线程中的 `SecurityContext`。
- MODE_GLOBAL：`SecurityContext` 在所有线程中都相同。

```java
//获取当前线程中的认证对象
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        //保存认证对象(一般用于自定义认证成功保存认证对象)
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        //清空认证对象(一般用于自定义登出清空认证对象)
        SecurityContextHolder.clearContext();
```

#### Authentication

Authentication即认证 辨明当前用户是谁 

```java
public interface Authentication extends Principal, Serializable {
    //获取用户权限  一般起你工况下获取到的是用户的角色信息
    Collection<? extends GrantedAuthority> getAuthorities();
	//获取证明用户的认证信息 通常情况下获取到的是密码 登陆成功后会被移除
    Object getCredentials();
	//获取用户的额外信息 IP地址和SessinID
    Object getDetails();
	//获取用户的身份信息 在未认证请跨国下获取到的是用户名在已认证的情况下获取到的是 UserDetails (暂时理解为，当前应用用户对象的扩展)
    Object getPrincipal();
	//判断是否是认证过的
    boolean isAuthenticated();
	//设置当前是否是认证过的
    void setAuthenticated(boolean var1) throws IllegalArgumentException;
}
```

##### AuthenticationManager、ProviderManager AuthenticationProvider



AuthenticationManager主要就是完成身份认证的流程

ProvicerManager 是AuthenticationManager具体的实现类

，ProviderManager里面有一个记录AuthenticationProvicer对象的集合属性 providers，AuthenticationProvider接口类里有两个方法

```java
public interface AuthenticationProvider {
    //实现具体的身份认证逻辑 认证失败抛出对应异常
    Authentication authenticate(Authentication var1) throws AuthenticationException;
	//判断认证类是否支持该Authentication的认证
    boolean supports(Class<?> var1);
}
```

接下来就是遍历 `ProviderManager` 里面的 `providers` 集合，找到和合适的 `AuthenticationProvider` 完成身份认证



##### UserDetailsService、UserDetails

UserDetailsService是一个接口只有一个方法`loadUserByUserName`

根据用户名查到对应的UserDetails对象

##### 流程

在运行到 `UsernamePasswordAuthenticationFilter` 过滤器的时候首先是进入其父类 `AbstractAuthenticationProcessingFilter` 的 `doFilter()` 方法中

```java
private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    //判断是否是配置的身份认证的URI
        if (!this.requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
        } else {
            try {
                //关键方法实现认证逻辑 并且返回Authentication由其字类UsernamePasswordAuthenticatioinFilter实现
                Authentication authenticationResult = this.attemptAuthentication(request, response);
                if (authenticationResult == null) {
                    return;
                }

                this.sessionStrategy.onAuthentication(authenticationResult, request, response);
                
                if (this.continueChainBeforeSuccessfulAuthentication) {
                    chain.doFilter(request, response);
                }
				//认证成功
                this.successfulAuthentication(request, response, chain, authenticationResult);
            } catch (InternalAuthenticationServiceException var5) {
                this.logger.error("An internal error occurred while trying to authenticate the user.", var5);
                this.unsuccessfulAuthentication(request, response, var5);
            } catch (AuthenticationException var6) {
                this.unsuccessfulAuthentication(request, response, var6);
            }

        }
    }
```

##### 认证失败处理逻辑

```java

protected void unsuccessfulAuthentication(...) {
    	//首先清除认证对象
		SecurityContextHolder.clearContext();
		this.rememberMeServices.loginFail(request, response);
    //这个方法处理认证失败页面跳转和相应逻辑 默认使用的是SimpleUrlAuthenticationFailureHandler实现类 可以自定义
        this.failureHandler.onAuthenticationFailure(request, response, failed);
}
  
```

###### SampleUriAuthenticationFailureHandler

```java
public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
    //如果没有配置默认登录失败跳转地址 直接相应错误
        if (this.defaultFailureUrl == null) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Sending 401 Unauthorized error since no failure URL is set");
            } else {
                this.logger.debug("Sending 401 Unauthorized error");
            }

            response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
        } else {
            //否则缓存异常
            this.saveException(request, exception);
            //根据跳转的页面是转发还是重定向进行不同方式的跳转
            if (this.forwardToDestination) {
                this.logger.debug("Forwarding to " + this.defaultFailureUrl);
                request.getRequestDispatcher(this.defaultFailureUrl).forward(request, response);
            } else {
                this.redirectStrategy.sendRedirect(request, response, this.defaultFailureUrl);
            }

        }
    }
//缓存异常的方法
protected final void saveException(HttpServletRequest request, AuthenticationException exception) {
    	//转发存储在request里
        if (this.forwardToDestination) {
            request.setAttribute("SPRING_SECURITY_LAST_EXCEPTION", exception);
        } else {
            //重定向存储在Session里
            HttpSession session = request.getSession(false);
            if (session != null || this.allowSessionCreation) {
                request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", exception);
            }

        }
    }

```

##### 认证成功处理逻辑

successfulAuthentication方法

```java
protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
    	//将认证完成的Authentication对象保存到当前线程的SecurityContext中
        SecurityContextHolder.getContext().setAuthentication(authResult);
        if (this.logger.isDebugEnabled()) {
            this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
        }

        this.rememberMeServices.loginSuccess(request, response, authResult);
        if (this.eventPublisher != null) {
            this.eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
        }
		//这个handler是为了完成登陆成功之后的页面跳转 默认使用SavedRequestAwareAuthenticationSuccessHandler 可以自定义
        this.successHandler.onAuthenticationSuccess(request, response, authResult);
    }
```



#### 身份认证详情

UsernamePasswordAuthenticationFilter

```java
//这个方法完成的就是身份认证的逻辑
public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (this.postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        } else {
            String username = this.obtainUsername(request);
            username = username != null ? username : "";
            username = username.trim();
            String password = this.obtainPassword(request);
            password = password != null ? password : "";
            //将前端传过来的用户和密码封装成一个UsernamePasswordAuthenticationToken类
            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
            this.setDetails(request, authRequest);
            //然后将具体的认证逻辑交给AuthenticationManager进行认证 默认使用的是ProviderManager 
            return this.getAuthenticationManager().authenticate(authRequest);
        }
    }
```

ProvideManager

```java
public class ProviderManager implements AuthenticationManager, MessageSourceAware,
        InitializingBean {
    ...
    private List<AuthenticationProvider> providers = Collections.emptyList();
    ...
    
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        ....
        //遍历所有的 AuthenticationProvider, 找到合适的完成身份验证
        for (AuthenticationProvider provider : getProviders()) {
            if (!provider.supports(toTest)) {
                continue;
            }
            ...
            try {
                //进行具体的身份验证逻辑, 这里使用到的是 DaoAuthenticationProvider, 具体逻辑记着往下看
                result = provider.authenticate(authentication);

                if (result != null) {
                    copyDetails(authentication, result);
                    break;
                }
            }
            catch 
            ...
        }
        ...
        throw lastException;
    }
}
```

DaoAUthenticationProvider继承自AbstractUserDetailsAuthenticationProvider 但是没有自己的认证方法 所以会调用父类的authenticate方法来完成认证

AbstractUserDetailsAuthenticationProvider 

```java
 public Authentication authenticate(Authentication authentication) throws AuthenticationException {
     //断言 如果不是UsernamePasswordAuthenticationToken的实现就会返回
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication, () -> {
            return this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports", "Only UsernamePasswordAuthenticationToken is supported");
        });
     //获取用户名
        String username = this.determineUsername(authentication);
        boolean cacheWasUsed = true;
     //根据用户名从缓存中查找UserDetails
        UserDetails user = this.userCache.getUserFromCache(username);
        if (user == null) {
            cacheWasUsed = false;

            try {
                //如果缓存中没有则就通过retrieveUser方法来查找(看下面 DaoAuthenticationProvider 的实现)
                user = this.retrieveUser(username, (UsernamePasswordAuthenticationToken)authentication);
            } 
            ....
            ....
        try {
             //比对前的检查,例如账户以一些状态信息(是否锁定, 过期...)
            this.preAuthenticationChecks.check(user);
            //子类实现比对规则 (看下面 DaoAuthenticationProvider 的实现)
            this.additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken)authentication);
        } catch (AuthenticationException var7) {
            if (!cacheWasUsed) {
                throw var7;
            }

            cacheWasUsed = false;
            user = this.retrieveUser(username, (UsernamePasswordAuthenticationToken)authentication);
            this.preAuthenticationChecks.check(user);
            this.additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken)authentication);
        }

        this.postAuthenticationChecks.check(user);
        if (!cacheWasUsed) {
            this.userCache.putUserInCache(user);
        }

        Object principalToReturn = user;
        if (this.forcePrincipalAsString) {
            principalToReturn = user.getUsername();
        }
//根据最终user的一些信息重新生成具体详细的 Authentication 对象并返回 
        return this.createSuccessAuthentication(principalToReturn, authentication, user);
    }
```

DaoAUthenticationProvider中的三个重要方法

retrieveUser----》获取需要比对的UserDetails

比对方式--》additionalAuthenticationChecks

返回最终的Authentication对象---》createSuccessAuthentication

additionalAuthenticationChecks

```java
//密码比对 
protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
     //如果密码为空返回一场
        if (authentication.getCredentials() == null) {
            this.logger.debug("Failed to authenticate since no credentials provided");
            throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        } else {
            //不为空通过从缓存中获取或者数据库中获取的USer对象进行密码比对
            String presentedPassword = authentication.getCredentials().toString();
            if (!this.passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
                this.logger.debug("Failed to authenticate since password does not match stored value");
                throw new BadCredentialsException(this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
            }
        }
    }

```

retrieveUsser

```java
//通过 UserDetailsService 获取 UserDetails
    protected final UserDetails retrieveUser(String username,
            UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        prepareTimingAttackProtection();
        try {
            //通过 UserDetailsService 获取 UserDetails
            UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
            if (loadedUser == null) {
                throw new InternalAuthenticationServiceException(
                        "UserDetailsService returned null, which is an interface contract violation");
            }
            return loadedUser;
        }
        catch (UsernameNotFoundException ex) {
            mitigateAgainstTimingAttack(authentication);
            throw ex;
        }
        catch (InternalAuthenticationServiceException ex) {
            throw ex;
        }
        catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
        }
    }
```

createSuccessAuthentication

```java
 //生成身份认证通过后最终返回的 Authentication, 记录认证的身份信息
    @Override
    protected Authentication createSuccessAuthentication(Object principal,
            Authentication authentication, UserDetails user) {
        boolean upgradeEncoding = this.userDetailsPasswordService != null
                && this.passwordEncoder.upgradeEncoding(user.getPassword());
        if (upgradeEncoding) {
            String presentedPassword = authentication.getCredentials().toString();
            String newPassword = this.passwordEncoder.encode(presentedPassword);
            user = this.userDetailsPasswordService.updatePassword(user, newPassword);
        }
        //将正确的密码放入Authentication对象中进行返回
        return super.createSuccessAuthentication(principal, authentication, user);
    }
}
```

