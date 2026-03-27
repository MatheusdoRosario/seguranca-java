package med.voll.web_application.domain.usuario;

import med.voll.web_application.domain.RegraDeNegocioException;
import med.voll.web_application.domain.usuario.email.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class UsuarioService implements UserDetailsService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private PasswordEncoder encriptador;

    @Autowired
    private EmailService emailService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return usuarioRepository.findByEmailIgnoreCase(username)
                .orElseThrow(() -> new UsernameNotFoundException("O usuário não foi encontrado!"));
    }

    public Long salvarUsuario(String nome, String email,  Perfil perfil) {
        var primeiraSenha = UUID.randomUUID().toString().substring(0, 8);
        System.out.println("Senha gerada: " + primeiraSenha);

        var senhaCriptografada = encriptador.encode(primeiraSenha);
        var usuario = usuarioRepository.save(new Usuario(nome, email, senhaCriptografada, perfil));

        emailService.enviarEmailSenhaAleatoria(usuario, primeiraSenha);

        return usuario.getId();
    }

    public void excluir(Long id) {
        usuarioRepository.deleteById(id);
    }

    public void alterarSenha(DadosAlteracaoSenha dados, Usuario logado) {
        if (!encriptador.matches(dados.senhaAtual(), logado.getPassword())) {
            throw new RegraDeNegocioException("Senha digitada não confere com a senha atual!");
        }

        if (!dados.novaSenha().equals(dados.novaSenhaConfirmacao())) {
            throw new RegraDeNegocioException("Senha e cofirmação não conferem");
        }

        String senhaCriptografada = encriptador.encode(dados.novaSenha());
        logado.alterarSenha(senhaCriptografada);
        logado.setSenhaAlterada(true);

        usuarioRepository.save(logado);
    }

    public void enviarToken(String email) {
        Usuario usuario = usuarioRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new RegraDeNegocioException("Usuário não encontrado!"));
        String token = UUID.randomUUID().toString();
        usuario.setToken(token);
        usuario.setExpiracaoToken(LocalDateTime.now().plusMinutes(30));

        usuarioRepository.save(usuario);
        emailService.enviarEmailSenha(usuario);
    }

    public void recuperarConta(String codigo, DadosRecuperacaoConta dados) {
        Usuario usuario = usuarioRepository.findByTokenIgnoreCase(codigo)
                .orElseThrow(() -> new RegraDeNegocioException("Link inválido!"));

        if (usuario.getExpiracaoToken().isBefore(LocalDateTime.now())) {
            throw new RegraDeNegocioException("Link expirado!");
        }

        if (!dados.novaSenha().equals(dados.novaSenhaConfirmacao())) {
            throw new RegraDeNegocioException("Senha e cofirmação não conferem");
        }

        String senhaCriptografada = encriptador.encode(dados.novaSenha());
        usuario.alterarSenha(senhaCriptografada);

        usuario.setToken(null);
        usuario.setExpiracaoToken(null);

        usuarioRepository.save(usuario);
    }
}
