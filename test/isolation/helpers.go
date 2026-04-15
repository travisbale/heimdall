package isolation

import "github.com/travisbale/heimdall/test/_util/setup"

// Shorthand aliases so test files stay concise
var (
	createAdminUser     = setup.CreateAdminUser
	createVerifiedUser  = setup.CreateVerifiedUser
	createUserInTenant  = setup.CreateUserInTenant
	getPermissionByName = setup.GetPermissionByName
)
