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