// UserController.java

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody UserDTO userDTO) {
        userService.registerUser(userDTO);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/dashboard")
    public ResponseEntity<String> userDashboard(Authentication authentication) {
        String role = authentication.getAuthorities().toString();
        if (role.contains("ADMIN")) {
            return ResponseEntity.ok("Admin Dashboard");
        } else {
            return ResponseEntity.ok("User Dashboard");
        }
    }
}

// UserService.java

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), new ArrayList<>());
    }

    public void registerUser(UserDTO userDTO) {
        User user = new User();
        user.setUsername(userDTO.getUsername());
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        user.setRole(userDTO.getRole());
        userRepository.save(user);
    }
}

// SecurityConfig.java

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/api/users/register").permitAll()
            .antMatchers("/api/users/dashboard").hasAnyRole("USER", "ADMIN")
            .and().formLogin();
    }
}

// User.java (Entity class representing a user)

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    private String username;

    @NotBlank
    private String password;

    @NotBlank
    private String role;

    // getters and setters
}

// UserDTO.java (Data Transfer Object for user registration)

public class UserDTO {

    @NotBlank
    private String username;

    @NotBlank
    private String password;

    @NotBlank
    private String role;

    // getters and setters
}

// UserRepository.java (Spring Data JPA repository for User entity)

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);
}
