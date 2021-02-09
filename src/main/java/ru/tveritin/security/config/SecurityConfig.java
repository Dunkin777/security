package ru.tveritin.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import ru.tveritin.security.model.Role;
import ru.tveritin.security.security.JwtConfigurer;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //права с помощью анотаций
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtConfigurer jwtConfigurer;

/*    private final UserDetailsService userDetailsService;*/ //мы его уже используем в jwt token provider

    @Autowired
    public SecurityConfig(JwtConfigurer jwtConfigurer/*@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService*/) {
        this.jwtConfigurer = jwtConfigurer;
/*        this.userDetailsService = userDetailsService;*/
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        //логика на основе ролей пользователя
/*        http
                .csrf().disable()//межсайтовая подделка запроса
                .authorizeRequests()
                .antMatchers("/").permitAll() //настраиваем доступ ролей по методам
                .antMatchers(HttpMethod.GET,"/api/**").hasAnyRole(Role.ADMIN.name(), Role.USER.name())
                .antMatchers(HttpMethod.POST, "/api/**").hasRole(Role.ADMIN.name()) //без слеша в начале URL не заработает
                .antMatchers(HttpMethod.DELETE, "/api/**").hasRole(Role.ADMIN.name())
                .anyRequest()//каждый запрос должен быть аунтефицирован (проверяться токен пользователя)
                .authenticated()
                .and()
                .httpBasic();*/

        //логика на основе прав пользователя
/*        http
                .csrf().disable()//межсайтовая подделка запроса
                .authorizeRequests()
                .antMatchers("/").permitAll() //настраиваем доступ ролей по методам
                .antMatchers(HttpMethod.GET,"/api/**").hasAuthority(Permission.Sellers_read.getPermission())
                .antMatchers(HttpMethod.POST, "/api/**").hasAuthority(Permission.Sellers_write.getPermission()) //без слеша в начале URL не заработает
                .antMatchers(HttpMethod.DELETE, "/api/**").hasAuthority(Permission.Sellers_write.getPermission())
                .anyRequest()//каждый запрос должен быть аунтефицирован (проверяться токен пользователя)
                .authenticated()
                .and()
                .httpBasic();*/ //header basic
        //логика на основе прав пользователя с помощью анотаций
/*        http
                .csrf().disable()//межсайтовая подделка запроса
                .authorizeRequests()
                .antMatchers("/").permitAll() //настраиваем доступ ролей по методам
                .anyRequest()//каждый запрос должен быть аунтефицирован (проверяться токен пользователя)
                .authenticated()
                .and()
                .formLogin()
                .loginPage("/auth/login").permitAll()//страница логина.
                .defaultSuccessUrl("/auth/success") //сюда нас перенаправляет при успешном логировании
                .and() //лог аут другой
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout", "POST")) //обрабатывает как пост
                .invalidateHttpSession(true) //обнуляет сессию
                .clearAuthentication(true) //забирает все права
                .deleteCookies("JSESSIONID") //чистит куки
                .logoutSuccessUrl("/auth/login"); //переводит на страницу логина*/

        //конфигурация без поддержания сессии
        http
                .csrf().disable()//межсайтовая подделка запроса
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/").permitAll() //настраиваем доступ ролей по методам
                .antMatchers("/api/v1/auth/login").permitAll()
                .anyRequest()//каждый запрос должен быть аунтефицирован (проверяться токен пользователя)
                .authenticated()
                .and()
                .apply(jwtConfigurer); //
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
/*    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }*/

    //строит юзеров в приложение
    @Bean
    @Override
    protected UserDetailsService userDetailsService() { //in memory storage
        return new InMemoryUserDetailsManager(
/*              User.builder().username("admin").password(passwordEncoder().encode("admin")).roles(Role.ADMIN.name()).build(),
                User.builder().username("user").password(passwordEncoder().encode("user")).roles(Role.USER.name()).build()*/
                User.builder().username("admin").password(passwordEncoder().encode("admin")).authorities(Role.ADMIN.getAuthorities()).build(),
                User.builder().username("user").password(passwordEncoder().encode("user")).authorities(Role.USER.getAuthorities()).build()
        );//строит новых пользователей с ролями
    }

    @Bean //если bean не поставить, то считай bean нет в приложении и пароль работать не будет
    protected PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(12);
    }

/*    @Bean
    //ПЕРЕДАЁМ ВСЁ? В КОНФИГУРАЦИЮ
    protected DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        //задаём энкодер на пароль
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        return daoAuthenticationProvider;
    }*/
}
