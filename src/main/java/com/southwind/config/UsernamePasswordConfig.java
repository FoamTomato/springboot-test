package com.southwind.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

public class UsernamePasswordConfig extends UsernamePasswordAuthenticationFilter {
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //说明以json的形式传递参数
        if(request.getContentType().equals(MediaType.APPLICATION_JSON_VALUE)||request.getContentType().equals(MediaType.APPLICATION_JSON_UTF8_VALUE)){
            String username=null;
            String password=null;
            Map<String,String> map= null;
            try {
                map = new ObjectMapper().readValue(request.getInputStream(), Map.class);

                username=map.get("username");
                password=map.get("password");
            } catch (IOException e) {
                e.printStackTrace();
            }
//            if(username==null){...}
//            if(password==null){...}
            username = username.trim();
            UsernamePasswordAuthenticationToken authRequest=new UsernamePasswordAuthenticationToken(username,password);

            setDetails(request,authRequest);
            return this.getAuthenticationManager().authenticate((authRequest));
        }
        //如果不是json就原计划获取
        return super.attemptAuthentication(request, response);
    }
}
