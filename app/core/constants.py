INJECTION_SAFE = r"^[^';\"\\<>]+$"
PASSWORD_SAFE = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]+$"

REGISTER_DESCRIPTION = "Registers an account. The username must be at least 6 characters long, and the password must be at least 16 characters long, using numbers, lowercase and uppercase letters, and safe special characters."
LOGIN_DESCRIPTION = "Login. The username must be at least 6 characters long, and the password must be at least 16 characters long, using numbers, lowercase and uppercase letters, and safe special characters."
ADD_PASSWORD_DESCRIPTION = "Stores site login credentials. The username must be at least 6 characters long, and the password must be at least 16 characters long, using numbers, lowercase and uppercase letters, and safe special characters."
GET_PASSWORD_DESCRIPTION = "Retrieves credentials for site login"