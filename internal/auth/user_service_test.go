package auth

// Test Helpers

type userServiceTestFixture struct {
	service              *UserService
	userDB               *mockUserDB
	hasher               *mockHasher
	emailService         *mockEmailService
	verificationTokenDB  *mockTokenDB
	passwordResetTokenDB *mockTokenDB
	loginAttempts        *mockLoginAttemptsService
	oidcService          *mockOIDCServiceForUser
}

func newUserServiceTestFixture() *userServiceTestFixture {
	userDB := newMockUserDB()
	hasher := &mockHasher{}
	emailService := &mockEmailService{}
	verificationTokenDB := newMockTokenDB()
	passwordResetTokenDB := newMockTokenDB()
	loginAttempts := &mockLoginAttemptsService{}
	oidcService := &mockOIDCServiceForUser{}
	rbacService := newMockRBACService()

	service := NewUserService(&UserServiceConfig{
		UserDB:               userDB,
		TenantsDB:            newMockTenantsDB(),
		Hasher:               hasher,
		EmailService:         emailService,
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
		emailService:         emailService,
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
