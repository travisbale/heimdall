package auth

type userServiceTestFixture struct {
	service              *UserService
	userDB               *mockUserDB
	hasher               *mockHasher
	emailClient          *mockEmailClient
	verificationTokenDB  *mockTokenDB
	passwordResetTokenDB *mockTokenDB
	loginAttempts        *mockLoginAttemptsService
	oidcService          *mockOIDCServiceForUser
}

func newUserServiceTestFixture() *userServiceTestFixture {
	userDB := newMockUserDB()
	hasher := &mockHasher{}
	emailClient := &mockEmailClient{}
	verificationTokenDB := newMockTokenDB()
	passwordResetTokenDB := newMockTokenDB()
	loginAttempts := &mockLoginAttemptsService{}
	oidcService := &mockOIDCServiceForUser{}
	rbacService := newMockRBACService()

	service := NewUserService(&UserServiceConfig{
		UserDB:               userDB,
		TenantsDB:            newMockTenantsDB(),
		Hasher:               hasher,
		EmailClient:          emailClient,
		VerificationTokenDB:  verificationTokenDB,
		PasswordResetTokenDB: passwordResetTokenDB,
		LoginAttemptsService: loginAttempts,
		OIDCService:          oidcService,
		RBACService:          rbacService,
		Logger:               &mockLogger{},
	})

	return &userServiceTestFixture{
		service:              service,
		userDB:               userDB,
		hasher:               hasher,
		emailClient:          emailClient,
		verificationTokenDB:  verificationTokenDB,
		passwordResetTokenDB: passwordResetTokenDB,
		loginAttempts:        loginAttempts,
		oidcService:          oidcService,
	}
}

// Helper function to add a user to mockUserDB (adds to both maps)
func addUserToMockDB(userDB *mockUserDB, user *User) {
	userDB.users[user.ID] = user
	userDB.emails[user.Email] = user
}
