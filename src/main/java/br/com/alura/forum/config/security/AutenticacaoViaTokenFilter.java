package br.com.alura.forum.config.security;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UsuarioRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class AutenticacaoViaTokenFilter extends OncePerRequestFilter {
    private TokenService tokenService;
    private UsuarioRepository repository;

    public AutenticacaoViaTokenFilter(TokenService tokenService, UsuarioRepository repository) {
        this.tokenService = tokenService;
        this.repository=repository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String token = recuperarToken(httpServletRequest);
        boolean valido = tokenService.isTokenValido(token);
        if(valido){
            autenticarUsuario(token);
        }
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }

    private void autenticarUsuario(String token) {
        Long idUsuario=tokenService.getIdUsuario(token);
       Usuario usuario= repository.findById(idUsuario).get();
        UsernamePasswordAuthenticationToken autentication = new UsernamePasswordAuthenticationToken(usuario,null,usuario.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(autentication);
    }

    private String recuperarToken(HttpServletRequest httpServletRequest){
        String token= httpServletRequest.getHeader("Authorization");
        if(token==null || token.isEmpty() || !token.startsWith("Bearer ")){
            return null;
        }
        return token.substring(7,token.length());
    }
}
