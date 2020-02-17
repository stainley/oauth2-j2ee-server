import model.AppDataRepository;
import model.User;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import javax.transaction.Transactional;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;

@ApplicationScoped
@Transactional
public class UserIdentityStore implements IdentityStore {

    @Inject
    private AppDataRepository appDataRepository;

    @Override
    public CredentialValidationResult validate(Credential credential) {
        UsernamePasswordCredential usernamePasswordCredential = (UsernamePasswordCredential) credential;
        String userId = usernamePasswordCredential.getCaller();
        User user = appDataRepository.getUser(userId);
        Objects.requireNonNull(user, "User should be not null");
        if (usernamePasswordCredential.getPasswordAsString().equals(user.getPassword())) {
            return new CredentialValidationResult(userId, new HashSet<>(Arrays.asList(user.getRoles().split(","))));
        }
        return CredentialValidationResult.INVALID_RESULT;
    }
}
