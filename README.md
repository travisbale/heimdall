# Heimdall Authentication API

> "Be warned, I shall uphold my sacred oath to protect this realm as its gatekeeper." ―Heimdall

Heimdall is a role based, authentication and authorization API service built using the Flask web framework. Each time a user tries to authenticate, Heimdall will verify their identity and issue them a [JSON Web Token](https://jwt.io/) that contains the roles and permissions that have been assigned to them.

Eventually, it will be possible for any application to use Heimdall to authenticate its users. The application will just need access to the SSH public key that Heimdall uses to sign tokens so that it can confirm the token's authenticity. Administrators are then able to create and assign whatever roles and permissions they need to their users to lock down and protect their application's endpoints.

## API Reference

Ultimately, I'd like to publish a Postman collection to properly document the API, but right now I just have a rudimentary testing collection setup [here](https://documenter.getpostman.com/view/4230650/TVYM5bhU). In the meantime I've listed and partially described the available endpoints below.

#### `POST /login`

- Authenticate a user given an email and password
- Issue new access and refresh tokens as HTTP only cookies

#### `POST /refresh`

- Retrieve a new access token if a valid refresh token is present in the request

#### `DELETE /logout`

- Revoke the issued access and refresh tokens

#### `POST /v1/users`

- Create a new user
- The `create:users` permission is required to access this endpoint

#### `DELETE /v1/users/{{id}}`

- Delete a specific user
- The `delete:users` permission is required to access the endpoint

#### `GET /v1/users/{{id}}/roles`

- Get the roles assigned to a user
- The `read:users` and `read:roles` permissions are required to access the endpoint

#### `POST /v1/users/{{id}}/roles`

- Assign roles to a user
- The `update:users` and `read:roles` permissions are required to access the endpoint

#### `DELETE /v1/users/{{id}}/roles`

- Unassign roles from a user
- The `update:users` and `read:roles` permissions are required to access the endpoint

#### `GET /v1/roles`

- Get the list of roles
- The `read:roles` permission is required to access the endpoint

#### `POST /v1/roles`

- Create a new role
- The `create:roles` permission is required to access the endpoint

#### `GET /v1/roles/{{id}}`

- Get a specific role
- The `read:roles` permission is required to access this endpoint

#### `DELETE /v1/roles/{{id}}`

- Delete a specific role
- The `delete:roles` permission is required to access the endpoint

#### `GET /v1/roles/{{id}}/permissions`

- Get the permissions assigned to a role
- The `read:roles` and `read:permissions` permissions are required to access the endpoint

#### `POST /v1/roles/{{id}}/permissions`

- Assign permissions to a role
- The `update:roles` and `read:permissions` permissions are required to access the endpoint

#### `DELETE /v1/roles/{{id}}/permissions`

- Unassign permissions to a role
- The `update:roles` and `read:permissions` permissions are required to access the endpoint

#### `GET /v1/permissions`

- Get the list of permissions
- The `read:permissions` permission is required to access the endpoint

#### `POST /v1/permissions`

- Create a new permission
- The `create:permissions` permission is required to access the endpoint

#### `GET /v1/permissions/{{id}}`

- Get a specific permission
- The `read:permissions` permission is required to access the endpoint

#### `DELETE /v1/permissions/{{id}}`

- Delete a specific permission
- The `delete:permissions` permission is required to access the endpoint

## Development Setup

By default Heimdall runs in its own docker container and uses a postgres database. Before spinning up the development environment there are several environment variables that must be defined, which I need to list in a sample .env file. It is also necessary to create SSH keys so that the tokens can be cryptographically signed before they are issued. The `ssh-keygen` utility can be used to create a public/private key pair that Heimdall can use. Once that's done, the development environment can be spun up by running `docker-compose up -d`.

Currently, an admin user needs to be bootstrapped into the database with all the permissions granted to them so they are able to read/write new roles, permissions, and users. I haven't decided exactly how I'd like to script that process, or if it would be better to just add another endpoint that can create some kind of admin user that automatically has all the administrator permissions assigned, so at this time it's manual.

## Built with

- [Flask](https://flask.palletsprojects.com/en/1.1.x/)
- [Flask-JWT-Extended](https://flask-jwt-extended.readthedocs.io/en/stable/)
- [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/en/2.x/)
- [Flask-Migrate](https://flask-migrate.readthedocs.io/en/latest/)
- [marshmallow](https://marshmallow.readthedocs.io/en/stable/index.html)
- [Docker](https://www.docker.com/)

## License

MIT © Travis Bale
