package mate.academy.service.impl;

import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import mate.academy.exception.AuthenticationException;
import mate.academy.exception.RegistrationException;
import mate.academy.lib.Inject;
import mate.academy.lib.Service;
import mate.academy.model.User;
import mate.academy.service.AuthenticationService;
import mate.academy.service.UserService;
import mate.academy.util.HashUtil;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    @Inject
    private UserService userService;

    @Override
    public User login(String email, String password) throws AuthenticationException {
        try {
            Optional<User> userFromDb = userService.findByEmail(email);
            if (userFromDb.isPresent()) {
                User user = userFromDb.get();
                String hashedPass = HashUtil.hashPassword(password, user.getSalt());
                if (user.getPassword().equals(hashedPass)) {
                    return user;
                }
            }
        } catch (NoSuchAlgorithmException e) {
            throw new AuthenticationException("Can`t log in", e);
        }
        throw new AuthenticationException("Invalid email or password");
    }

    @Override
    public User register(String email, String password) throws RegistrationException {
        User user = null;
        try {
            Optional<User> existingUser = userService.findByEmail(email);
            if (existingUser.isPresent()) {
                throw new RegistrationException("User already exists");
            }
            user = new User();
            user.setEmail(email);
            String salt = HashUtil.generateSalt();
            String hashedPassword = HashUtil.hashPassword(password, salt);
            user.setSalt(salt);
            user.setPassword(hashedPassword);
            userService.add(user);
        } catch (NoSuchAlgorithmException e) {
            throw new RegistrationException("Can`t register user", e);
        }
        return user;
    }
}
