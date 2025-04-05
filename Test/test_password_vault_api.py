import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import Base, engine, SessionLocal

# --- Setup Test Environment ---
@pytest.fixture(scope="module")
def test_client():
    # Create the test database schema
    Base.metadata.create_all(bind=engine)
    client = TestClient(app)
    yield client
    # Drop all tables after tests
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Shared Values ---
TEST_USER = {"username": "testuser", "password": "StrongP@ssw0rd12345"}
VAULT_ENTRY = {
    "site_name": "Gmail",
    "site_username": "randomusername",
    "site_password": "SiteP@ss123456789009"
}

HTTP_422_UNPROCESSABLE_ENTITY = 422
HTTP_401_UNAUTHORIZED = 401
HTTP_200_OK = 200
HTTP_403_FORBIDDEN = 403
HTTP_404_NOT_FOUND = 404
HTTP_409_CONFLICT = 409

TEST_SHORT_USERNAME="abcd"
TEST_VALID_WRONG_PASSWORD="WrongWrong123456!"
TEST_INVALID_SHORT_PASSWORD="Wrong@12"
TEST_INVALID_PASS_MISSING_NUMBER="WrongWrong!!!!!@!"
TEST_INVALID_PASS_MISSING_UPPER="wrongwrong123!!!!@"
TEST_INVALID_PASS_MISSING_LOWER="WRONGWRONG123!!!"
TEST_INVALID_PASS_MISSING_SPECIAL="WRONGWroONG12345678"
TEST_INJECTED_INPUT_BACK_SLASH="Wrong@123Wrong@12g\\"
TEST_INJECTED_INPUT_SEMICOLON="WrongWrong123@456;;;"
TEST_INJECTED_INPUT_DOUBLE_QUOTE="WrongWrong@123456\""
TEST_INJECTED_INPUT_SINGLE_QUOTE="WrongWrong@123456\'"
TEST_INJECTED_INPUT_HTML_TAG="WrongWrong@123456<>"


# --- Helper ---
def get_auth_tokens(client):
    client.post("/register", json=TEST_USER)

    res = client.post("/login", json=TEST_USER)
    assert res.status_code == HTTP_200_OK, f"Login failed: {res.json()}"
    tokens = res.json()
    assert "access_token" in tokens, "access_token not in response"
    assert "refresh_token" in tokens, "refresh_token not in response"
    return tokens["access_token"], tokens["refresh_token"]

# --- Tests ---


# ----------------
# --- REGISTER ---
# ----------------

def test_register_invalid_username_short_length(test_client):
    res = test_client.post("/register", json={"username": TEST_SHORT_USERNAME, "password": TEST_VALID_WRONG_PASSWORD})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_username_backslash(test_client):
    res = test_client.post("/register", json={"username": TEST_INJECTED_INPUT_BACK_SLASH, "password": TEST_USER["password"]})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_username_semicolon(test_client):
    res = test_client.post("/register", json={"username": TEST_INJECTED_INPUT_SEMICOLON, "password": TEST_USER["password"]})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_username_double_quote(test_client):
    res = test_client.post("/register", json={"username": TEST_INJECTED_INPUT_DOUBLE_QUOTE, "password": TEST_USER["password"]})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_username_single_quote(test_client):
    res = test_client.post("/register", json={"username": TEST_INJECTED_INPUT_SINGLE_QUOTE, "password": TEST_USER["password"]})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_username_html_tag(test_client):
    res = test_client.post("/register", json={"username": TEST_INJECTED_INPUT_HTML_TAG, "password": TEST_USER["password"]})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_password_short_length(test_client):
    res = test_client.post("/register", json={"username": TEST_USER["username"], "password": TEST_INVALID_SHORT_PASSWORD})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_password_number_missing(test_client):
    res = test_client.post("/register", json={"username": TEST_USER["username"], "password": TEST_INVALID_PASS_MISSING_NUMBER})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_password_upper_letter_missing(test_client):
    res = test_client.post("/register", json={"username": TEST_USER["username"], "password": TEST_INVALID_PASS_MISSING_UPPER})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_password_lower_letter_missing(test_client):
    res = test_client.post("/register", json={"username": TEST_USER["username"], "password": TEST_INVALID_PASS_MISSING_LOWER})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_password_special_char_missing(test_client):
    res = test_client.post("/register", json={"username": TEST_USER["username"], "password": TEST_INVALID_PASS_MISSING_SPECIAL})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_password_backslash(test_client):
    res = test_client.post("/register", json={"username": TEST_USER["username"], "password": TEST_INJECTED_INPUT_BACK_SLASH})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_password_semicolon(test_client):
    res = test_client.post("/register", json={"username": TEST_USER["username"], "password": TEST_INJECTED_INPUT_SEMICOLON})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_password_double_quote(test_client):
    res = test_client.post("/register", json={"username": TEST_USER["username"], "password": TEST_INJECTED_INPUT_DOUBLE_QUOTE})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_password_single_quote(test_client):
    res = test_client.post("/register", json={"username": TEST_USER["username"], "password": TEST_INJECTED_INPUT_SINGLE_QUOTE})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_invalid_password_html_tag(test_client):
    res = test_client.post("/register", json={"username": TEST_USER["username"], "password": TEST_INJECTED_INPUT_HTML_TAG})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_register_success(test_client):
    res = test_client.post("/register", json=TEST_USER)
    assert res.status_code == HTTP_200_OK
    assert "access_token" in res.json()
    assert "refresh_token" in res.json()

    res = test_client.post("/login", json=TEST_USER)
    assert res.status_code == HTTP_200_OK
    assert "access_token" in res.json()


def test_register_duplicate_user(test_client):
    res = test_client.post("/register", json=TEST_USER)
    assert res.status_code == HTTP_409_CONFLICT

# -------------
# --- LOGIN ---
# -------------

def test_login_invalid_username_short_length(test_client):
    res = test_client.post("/login", json={"username": TEST_SHORT_USERNAME, "password": TEST_VALID_WRONG_PASSWORD})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_username_backslash(test_client):
    res = test_client.post("/login", json={"username": TEST_INJECTED_INPUT_BACK_SLASH, "password": TEST_USER["password"]})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_username_semicolon(test_client):
    res = test_client.post("/login", json={"username": TEST_INJECTED_INPUT_SEMICOLON, "password": TEST_USER["password"]})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_username_double_quote(test_client):
    res = test_client.post("/login", json={"username": TEST_INJECTED_INPUT_DOUBLE_QUOTE, "password": TEST_USER["password"]})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_username_single_quote(test_client):
    res = test_client.post("/login", json={"username": TEST_INJECTED_INPUT_SINGLE_QUOTE, "password": TEST_USER["password"]})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_username_html_tag(test_client):
    res = test_client.post("/login", json={"username": TEST_INJECTED_INPUT_HTML_TAG, "password": TEST_USER["password"]})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_password_not_match(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_VALID_WRONG_PASSWORD})
    assert res.status_code == HTTP_401_UNAUTHORIZED


def test_login_invalid_password_short_length(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_INVALID_SHORT_PASSWORD})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_password_number_missing(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_INVALID_PASS_MISSING_NUMBER})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_password_upper_letter_missing(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_INVALID_PASS_MISSING_UPPER})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_password_lower_letter_missing(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_INVALID_PASS_MISSING_LOWER})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_password_special_char_missing(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_INVALID_PASS_MISSING_SPECIAL})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_password_backslash(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_INJECTED_INPUT_BACK_SLASH})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_password_semicolon(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_INJECTED_INPUT_SEMICOLON})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_password_double_quote(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_INJECTED_INPUT_DOUBLE_QUOTE})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_password_single_quote(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_INJECTED_INPUT_SINGLE_QUOTE})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_login_invalid_password_html_tag(test_client):
    res = test_client.post("/login", json={"username": TEST_USER["username"], "password": TEST_INJECTED_INPUT_HTML_TAG})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY

# --------------------
# --- Add Password ---
# --------------------

def test_add_password_success(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json=VAULT_ENTRY, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_200_OK
    assert res.json()["message"] == "Password stored successfully."


def test_add_duplicate_password(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json=VAULT_ENTRY, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_409_CONFLICT


def test_add_password_invalid_site_name_backslash(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": TEST_INJECTED_INPUT_BACK_SLASH, "site_username": VAULT_ENTRY["site_username"], "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_site_name_semicolon(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": TEST_INJECTED_INPUT_SEMICOLON, "site_username": VAULT_ENTRY["site_username"], "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_site_name_double_quote(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": TEST_INJECTED_INPUT_DOUBLE_QUOTE, "site_username": VAULT_ENTRY["site_username"], "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_site_name_single_quote(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": TEST_INJECTED_INPUT_SINGLE_QUOTE, "site_username": VAULT_ENTRY["site_username"], "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_site_name_html_tag(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": TEST_INJECTED_INPUT_HTML_TAG, "site_username": VAULT_ENTRY["site_username"], "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_site_username_short_length(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": TEST_SHORT_USERNAME, "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_site_username_backslash(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": TEST_INJECTED_INPUT_BACK_SLASH, "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_site_username_semicolon(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": TEST_INJECTED_INPUT_SEMICOLON, "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_site_username_double_quote(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": TEST_INJECTED_INPUT_DOUBLE_QUOTE, "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_site_username_single_quote(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": TEST_INJECTED_INPUT_SINGLE_QUOTE, "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_site_username_html_tag(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": TEST_INJECTED_INPUT_HTML_TAG, "site_password": VAULT_ENTRY["site_password"]}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_password_short_length(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"], "site_password": TEST_INVALID_SHORT_PASSWORD}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_password_number_missing(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"], "site_password": TEST_INVALID_PASS_MISSING_NUMBER}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_password_upper_letter_missing(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"], "site_password": TEST_INVALID_PASS_MISSING_UPPER}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_password_lower_letter_missing(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"], "site_password": TEST_INVALID_PASS_MISSING_LOWER}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_password_special_char_missing(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"], "site_password": TEST_INVALID_PASS_MISSING_SPECIAL}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_password_backslash(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"], "site_password": TEST_INJECTED_INPUT_BACK_SLASH}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_password_semicolon(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"], "site_password": TEST_INJECTED_INPUT_SEMICOLON}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_password_double_quote(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"], "site_password": TEST_INJECTED_INPUT_DOUBLE_QUOTE}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_password_single_quote(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"], "site_password": TEST_INJECTED_INPUT_SINGLE_QUOTE}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_invalid_password_html_tag(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/vault/add", json={ "site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"], "site_password": TEST_INJECTED_INPUT_HTML_TAG}, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_add_password_unauthorized(test_client):
    res = test_client.post("/vault/add", json=VAULT_ENTRY)
    assert res.status_code == HTTP_403_FORBIDDEN or res.status_code == HTTP_401_UNAUTHORIZED

# --------------------
# --- GET Password ---
# --------------------

def test_get_password_not_found(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": "Twitter", "site_username": "randomusername"}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_404_NOT_FOUND


def test_get_password_invalid_site_name_backslash(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": TEST_INJECTED_INPUT_BACK_SLASH, "site_username": "randomusername"}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_invalid_site_name_semicolon(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": TEST_INJECTED_INPUT_SEMICOLON, "site_username": "randomusername"}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_invalid_site_name_double_quote(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": TEST_INJECTED_INPUT_DOUBLE_QUOTE, "site_username": "randomusername"}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_invalid_site_name_single_quote(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": TEST_INJECTED_INPUT_SINGLE_QUOTE, "site_username": "randomusername"}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_invalid_site_name_html_tag(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": TEST_INJECTED_INPUT_HTML_TAG, "site_username": "randomusername"}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_invalid_site_username_short_length(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": "Amazon", "site_username": TEST_SHORT_USERNAME}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_invalid_site_username_backslash(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": "Amazon", "site_username": TEST_INJECTED_INPUT_BACK_SLASH}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_invalid_site_username_semicolon(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": "Amazon", "site_username": TEST_INJECTED_INPUT_SEMICOLON}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_invalid_site_username_double_quote(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": "Amazon", "site_username": TEST_INJECTED_INPUT_DOUBLE_QUOTE}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_invalid_site_username_single_quote(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": "Amazon", "site_username": TEST_INJECTED_INPUT_SINGLE_QUOTE}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_invalid_site_username_html_tag(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": "Amazon", "site_username": TEST_INJECTED_INPUT_HTML_TAG}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_422_UNPROCESSABLE_ENTITY


def test_get_password_unauthorized(test_client):
    params = {"site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"]}
    res = test_client.get("/vault/", params=params)
    assert res.status_code == HTTP_403_FORBIDDEN or res.status_code == HTTP_401_UNAUTHORIZED


def test_get_password_success(test_client):
    access_token, _ = get_auth_tokens(test_client)
    params = {"site_name": VAULT_ENTRY["site_name"], "site_username": VAULT_ENTRY["site_username"]}
    res = test_client.get("/vault/", params=params, headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_200_OK
    data = res.json()
    assert data["site_name"] == VAULT_ENTRY["site_name"]
    assert data["site_username"] == VAULT_ENTRY["site_username"]
    assert "site_password" in data


# ---------------------
# --- Refresh Token ---
# ---------------------


def test_refresh_token_flow(test_client):
    _, refresh_token = get_auth_tokens(test_client)
    headers = {"Authorization": f"Bearer {refresh_token}"}
    res = test_client.post("/refresh-token", headers=headers)
    assert res.status_code == HTTP_200_OK
    assert "access_token" in res.json()


def test_refresh_token_invalid_type(test_client):
    access_token, _ = get_auth_tokens(test_client)
    res = test_client.post("/refresh-token", headers={"Authorization": f"Bearer {access_token}"})
    assert res.status_code == HTTP_401_UNAUTHORIZED

