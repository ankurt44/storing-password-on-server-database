# Secure storing of user password in server database.

Simple REST API backend using express framework.
Encrypt password using bcrypt.hash(...). Use salt for added security. The hashed password is stored in database together with salt and other details.
Validate password at the time of login using bcrypt.compare(...).

ToDo: Refactor/Add details.
