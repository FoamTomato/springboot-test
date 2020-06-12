package com.southwind.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@EnableWebSecurity
@Configuration
public class ScurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${login.urls}")
    private  String loginUrle;

    private static final Logger log = LoggerFactory.getLogger(ScurityConfig.class);

    /**
     * 成功
     */
    private static final String SUCCESS = "{\"result_code\": \"f200\", \"result_msg\": \"登录成功\"}";
    /**
     * 注销
     */
    private static final String OUTFO = "{\"result_code\": \"f200\", \"result_msg\": \"注销成功\"}";
    /**
     * 失败
     */
    private static final String FAILED = "{\"result_code\": \"f401\", \"result_msg\": \"登录失败\"}";

    /**
     * 登录过期
     */
    private static final String LOGIN_EXPIRE = "{\"result_code\": \"f402\", \"result_msg\": \"登录过期\"}";

    /**
     * 权限限制
     */
    private static final String ROLE_LIMIT = "{\"result_code\": \"10002\", \"result_msg\": \"权限不足\"}";

    /**
     * 登录 URL
     */
    private static final String LOGIN_URL = "/authc/login";

    /**
     * 登出 URL
     */
    private static final String LOGOUT_URL = "/logouts";

    /**
     * 授权 URL
     */
    private static final String AUTH_URL_REG = "/authc/**";

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        //定制请求的授权规则
        http.cors().and()
                .csrf().disable()
                .authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/employee/**").hasRole("vip2")
        //.antMatchers(HttpMethod.OPTIONS).permitAll()
//                .and()
//                .exceptionHandling().authenticationEntryPoint(new CustomAuthenticationEntryPoint())
        ;
        http
                /*
                异常处理
                默认 权限不足  返回403，可以在这里自定义返回内容
                 */
                .exceptionHandling()
                .accessDeniedHandler(new DefinedAccessDeniedHandler())
                .authenticationEntryPoint(new DefinedAuthenticationEntryPoint());

        System.out.println(123);
        //开启自动配置的登录功能，如果没有登录没有权限就会来到登录页面
        //http.formLogin();
        //http.formLogin().loginPage(loginUrl);//自定义登录界面
        http.formLogin()//.usernameParameter("username") //登录账号name
               // .passwordParameter("password")       //登录密码name
                //.loginPage("/login")
                .successForwardUrl("/logins");
        http.addFilterAt(myFilter(), UsernamePasswordAuthenticationFilter.class);
        //.loginPage(loginUrle);       //定制登录界面
                //.loginProcessingUrl("/logins");  //请求登录地址
        //get方式去登录页
        //post方式处理登录请求
        //login?error 错误
        //login?logout 退出
        //注销
        http
                .logout()
                .logoutUrl(LOGOUT_URL)
                .invalidateHttpSession(true)
                .invalidateHttpSession(true)
                .logoutSuccessHandler(new DefinedLogoutSuccessHandler());
        //1./login来到登录页
        //2./login?error 重定向表示登录失败
        //3.更多详细规定
        //4.一但定制loingPage，那么loginPage的post请求就是登录
        //开启自动配置的注销功能
        //http.logout();
        //http.logout().logoutSuccessUrl("/");//注销成功跳转页面
        //1.访问/logout 表示用户注销并清空session
        //2.注销成功会返回 /login?logout

        //开启记住我功能
        //http.rememberMe();
        http.rememberMe();//记住我name

        //登录成功以后，将cookie发给浏览器保存，以后登录带上这个cookie，只要通过检查就可以免登录
        //点击注销会删除cookie
    }
    //定义认证规则
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
//        auth.inMemoryAuthentication()
//                .withUser("lis").password("123").roles("vip2","vip3");
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("lis").password(new BCryptPasswordEncoder().encode("123")).roles("vip2");
    }

    @Bean
    UsernamePasswordConfig myFilter() throws Exception{
        UsernamePasswordConfig filter=new UsernamePasswordConfig();

        //将存有的身份信息传进去
        filter.setAuthenticationManager(super.authenticationManagerBean());
        filter.setFilterProcessesUrl("/jsonLogin");

        //filter.setRememberMeServices(RememberMeServices);
        //登录成功
        //filter.setAuthenticationSuccessHandler(new DefinedAuthenticationSuccessHandler());
        filter.setAuthenticationSuccessHandler(new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                //httpServletResponse.setContentType("application/json");
                httpServletResponse.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
                PrintWriter out=httpServletResponse.getWriter();
                Map<String,Object> map=new HashMap<>();
                map.put("result_code","f200");
                map.put("result_msg","登录成功");
                map.put("msg",authentication.getPrincipal());//存放着身份信息的类

                out.write(new ObjectMapper().writeValueAsString(map));
                out.flush();
                out.close();
            }

        });
        //登录失败后
        filter.setAuthenticationFailureHandler(new DefindeAuthenticationFailureHandler());
        return filter;
    }

    /**
     * 授权成功handler
     */
    class DefinedAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            log.info("用户登录成功 [{}]", authentication.getName());
            // 获取登录成功信息
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(SUCCESS);
        }
    }

    /**
     * 登出成功hanlder
     */
    class DefinedLogoutSuccessHandler implements LogoutSuccessHandler {
        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            log.info("注销成功 [{}]", null != authentication ? authentication.getName() : null);
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(OUTFO);
        }
    }

    /**
     * 授权失败handler
     */
    class DefindeAuthenticationFailureHandler implements AuthenticationFailureHandler {
        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
            log.info("用户登录失败 [{}]", exception.getMessage());
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(FAILED);
        }
    }

    /**
     * 授权handler
     */
    class DefinedAuthenticationEntryPoint implements AuthenticationEntryPoint {
        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
            if (log.isDebugEnabled()) {
                log.debug("登录过期 [{}]", authException.getMessage());
            }
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(LOGIN_EXPIRE);
        }
    }

    /**
     * 权限handler
     */
    class DefinedAccessDeniedHandler implements AccessDeniedHandler {
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
            if (log.isDebugEnabled()) {
                log.debug("权限不足 [{}]", accessDeniedException.getMessage());
            }
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.getWriter().write(ROLE_LIMIT);
        }
    }
}
