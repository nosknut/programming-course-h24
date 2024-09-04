import os
import json
import logging
import hashlib
import secrets
import datetime
from flask import Flask, request
from dotenv import load_dotenv

app = Flask(__name__)

env_filename = "access_token_demo.env"
cwd = os.path.dirname(__file__)
env_file_path = os.path.join(cwd, env_filename)

load_dotenv(env_file_path)


def getenv_or_error(env_var_name):
    value = os.getenv(env_var_name)
    if value is None:
        raise ValueError(f"Missing environment variable: {env_var_name}")
    return value


SALT = getenv_or_error("SALT")
PORT = getenv_or_error("PORT")
HOST = getenv_or_error("HOST")
ACCESS_TOKEN_EXPIRE_DURATION_DAYS = int(getenv_or_error("ACCESS_TOKEN_EXPIRE_DURATION_DAYS"))
DATABASE_FILE_PATH = getenv_or_error("DATABASE_FILE_PATH")

database_file_path = os.path.join(cwd, DATABASE_FILE_PATH)

website_file_path = os.path.join(cwd, "access_token_demo_website.html")

def make_empty_database():
    return {
        "users": {},
        "roles": {},
        "password_hashes": {},
        "access_tokens": {},
        "grades": {},
    }

database = make_empty_database()

def load_database():
    global database
    database = json.load(open(database_file_path))


def write_database():
    json.dump(database, open(database_file_path, "w"), indent=4)


def hash_password(password, salt):
    salted_password = salt + password
    return hashlib.sha256(salted_password.encode()).hexdigest()


def check_password(username, password, salt):
    user = database["password_hashes"].get(username)
    if user is None:
        return False
    return hash_password(password, salt) == user["password_hash"]


def create_access_token(username, device_name):
    # Generate a 32 character long random access token
    access_token = secrets.token_hex(16)
    access_token_expire_date = datetime.datetime.now() + datetime.timedelta(
        hours=24*ACCESS_TOKEN_EXPIRE_DURATION_DAYS
    )
    
    token_entry = {
        "username": username,
        "device_name": device_name,
        "expires": access_token_expire_date.timestamp(),
        "token": access_token,
    }

    database["access_tokens"][access_token] = token_entry

    write_database()

    return token_entry

@app.route("/users/<username>/tokens", methods=["POST"])
def login(username):
    # Pull the json data from the request body
    data = request.json
    username = data.get("username")
    password = data.get("password")
    device_name = data.get("device_name")

    is_self = username == username
    if not is_self:
        # Respond with a json formatted error message and a Http Status Code: "403 Forbidden"
        return ({"error": "Unauthorized"}, 403)

    if username is None or password is None:
        response_payload = {"error": "Missing username or password"}
        return (response_payload, 400) # Http Status: "400 Bad Request"

    if not check_password(username, password, SALT):
        response_payload = {"error": "Invalid username or password"}
        return (response_payload, 401)  # Http Status: "401 Unauthorized"

    access_token_entry = create_access_token(username, device_name)

    # Respond with a json formatted user data and a Http Status Code: "200 OK"
    return (access_token_entry, 200)

@app.route("/users/<username>/tokens", methods=["GET"])
def list_tokens(username):
    authorized, authorization_result = authorize(request)
    if not authorized:
        return authorization_result
    logged_in_user = authorization_result

    is_self = logged_in_user == username
    if not is_self:
        return ({"error": "Unauthorized"}, 403) # Http Status: "403 Forbidden"

    # Limits the number of tokens to be returned
    limit = int(request.args.get("limit", 10))
    
    # find all tokens belonging  to the user
    user_tokens = []
    
    for token in database["access_tokens"].values():
        if token["username"] == username:
            user_tokens.append(token)
    
    # Apply the limit from the Query String/URL Parameters
    filtered_user_tokens = user_tokens[:limit]
    
    response_body = {
        "tokens": filtered_user_tokens,
        "count": len(filtered_user_tokens),
        "total_count": len(user_tokens),
        "limit": limit,
    }
    
    return (response_body, 200)
    

@app.route("/users/<username>/tokens/<token>", methods=["DELETE"])
def delete_access_token(username, token):
    authorized, authorization_result = authorize(request)
    if not authorized:
        return authorization_result
    logged_in_user = authorization_result

    is_self = logged_in_user == username
    if not is_self:
        return ({"error": "Unauthorized"}, 403) # Http Status: "403 Forbidden"

    access_token_data = database["access_tokens"].get(token)
    if access_token_data is None:
        return (
            {"error": "Invalid access token"},
            401,
        )  # Http Status: "401 Unauthorized"

    if access_token_data["username"] != logged_in_user:
        return ({"error": "Unauthorized"}, 403)  # Http Status: "403 Forbidden"

    del database["access_tokens"][token]
    write_database()

    return ({"message": "Access token deleted"}, 200)  # Http Status: "200 OK"

@app.route("/users/<username>/tokens/<token>", methods=["GET"])
def get_access_token(username, token):
    authorized, authorization_result = authorize(request)
    if not authorized:
        return authorization_result
    logged_in_user = authorization_result

    is_self = logged_in_user == username
    if not is_self:
        return ({"error": "Unauthorized"}, 403) # Http Status: "403 Forbidden"

    access_token_data = database["access_tokens"].get(token)
    if access_token_data is None:
        return (
            {"error": "Invalid access token"},
            404,
        )  # Http Status: "404 Not Found"

    if access_token_data["username"] != logged_in_user:
        return ({"error": "Unauthorized"}, 403)  # Http Status: "403 Forbidden"

    entry = database["access_tokens"][token]

    return (entry, 200)  # Http Status: "200 OK"

def authorize(request):
    """
    Returns (True, username) if the request is authorized, otherwise (False, error_response)
    """

    authorization_header = request.headers.get("Authorization")

    if authorization_header is None:
        return (
            False,
            ({"error": "Missing access token"}, 401),
        )  # Http Status: "401 Unauthorized"

    token_type, token = authorization_header.split(" ")
    if token_type != "Bearer":
        return (
            False,
            ({"error": "Invalid access token"}, 401),
        )  # Http Status: "401 Unauthorized"

    access_token_data = database["access_tokens"].get(token)
    if access_token_data is None:
        return (
            False,
            ({"error": "Invalid access token"}, 401),
        )  # Http Status: "401 Unauthorized"

    if access_token_data["expires"] < datetime.datetime.now().timestamp():
        return (
            False,
            ({"error": "Access token expired"}, 401),
        )  # Http Status: "401 Unauthorized"

    return (True, access_token_data["username"])

@app.route("/users/<username>/profile", methods=["GET"])
def get_user(username):
    authorized, authorization_result = authorize(request)
    if not authorized:
        return authorization_result
    logged_in_user = authorization_result

    is_self = logged_in_user == username
    is_teacher = has_role("teacher", logged_in_user)

    if (not is_self) and (not is_teacher):
        return ({"error": "Unauthorized"}, 403)  # Http Status: "403 Forbidden"

    user = database["users"].get(username)
    if user is None:
        return ({"error": "User not found"}, 404)  # Http Status: "404 Not Found"

    return (user, 200)  # Http Status: "200 OK"


@app.route("/users/<username>/profile", methods=["PUT"])
def update_user(username):
    authorized, authorization_result = authorize(request)
    if not authorized:
        return authorization_result
    logged_in_user = authorization_result

    is_self = logged_in_user == username

    if not is_self:
        return ({"error": "Unauthorized"}, 403)  # Http Status: "403 Forbidden"

    data = request.json

    if data is None:
        return ({"error": "Missing user data"}, 400)  # Http Status: "400 Bad Request"

    if data["username"] != username:
        return (
            {"error": "Username cannot be changed"},
            400,
        )  # Http Status: "400 Bad Request"

    database["users"][username] = data
    
    write_database()

    return (data, 200)  # Http Status: "200 OK"


def has_role(role, username):
    return role in database["roles"].get(username, [])


@app.route("/users/<username>/grades", methods=["GET"])
def get_grades(username):
    authorized, authorization_result = authorize(request)
    if not authorized:
        return authorization_result
    logged_in_user = authorization_result

    # Check if the logged in user (the user from the access token)
    # is authorized to access the grades of the user from the URL
    is_self = logged_in_user == username
    is_teacher = has_role("teacher", logged_in_user)

    if (not is_self) and (not is_teacher):
        return ({"error": "Unauthorized"}, 403)  # Http Status: "403 Forbidden"

    grades = database["grades"].get(username)
    if grades is None:
        return ({"error": "Grades not found"}, 404)  # Http Status: "404 Not Found"

    return (grades, 200)  # Http Status: "200 OK"


@app.route("/users/<username>/grades", methods=["POST"])
def set_grades(username):
    authorized, authorization_result = authorize(request)
    if not authorized:
        return authorization_result
    logged_in_user = authorization_result

    # Check if the logged in user (the user from the access token)
    # is authorized to set the grades of the user from the URL
    is_teacher = has_role("teacher", logged_in_user)

    if not is_teacher:
        return ({"error": "Unauthorized"}, 403)  # Http Status: "403 Forbidden"

    # Pull the json data from the request body
    data = request.json
    if data is None:
        return ({"error": "Missing grades data"}, 400)  # Http Status: "400 Bad Request"

    database["grades"][username] = data
    
    write_database()

    # A post endpoint should respond with the created data
    return (data, 200)  # Http Status: "200 OK"


@app.route("/users/<username>/grades", methods=["DELETE"])
def delete_grades(username):
    authorized, authorization_result = authorize(request)
    if not authorized:
        return authorization_result
    logged_in_user = authorization_result

    # Check if the logged in user (the user from the access token)
    # is authorized to set the grades of the user from the URL
    is_teacher = has_role("teacher", logged_in_user)

    if not is_teacher:
        return ({"error": "Unauthorized"}, 403)
    
    del database["grades"][username]
    
    write_database()
    
    return ({"message": "Grades deleted"}, 200)  # Http Status: "200 OK"


# create user route
@app.route("/users", methods=["POST"])
def create_user():
    # Pull the json data from the request body
    data = request.json
    username = data.get("username")
    age = data.get("age")
    email = data.get("email")
    password = data.get("password")
    roles = data.get("roles")
    device_name = data.get("device_name")

    if (
        username is None
        or password is None
        or email is None
        or age is None
        or device_name is None
    ):
        return (
            {"error": "Incomplete user info"},
            400,
        )  # Http Status: "400 Bad Request"

    if database["password_hashes"].get(username) is not None:
        return ({"error": "User already exists"}, 400)  # Http Status: "400 Bad Request"

    database["users"][username] = {
        "username": username,
        "age": age,
        "email": email,
    }

    database["roles"][username] = roles

    database["password_hashes"][username] = {
        "username": username,
        "password_hash": hash_password(password, SALT),
    }

    access_token = create_access_token(username, device_name)

    write_database()

    # Respond with a json formatted user data and a http status code: "200 OK"
    response_payload = {
        "user": database["users"][username],
        "access_token": access_token,
        "url": f"/users/{username}",
    }

    return (response_payload, 200)


@app.route("/users/<username>", methods=["DELETE"])
def delete_user(username):
    authorized, authorization_result = authorize(request)
    if not authorized:
        return authorization_result
    logged_in_user = authorization_result

    if logged_in_user != username:
        return ({"error": "Unauthorized"}, 403)  # Http Status: "403 Forbidden"

    del database["users"][username]
    del database["roles"][username]
    del database["password_hashes"][username]
    
    if username in database["grades"]:
        del database["grades"][username]
    
    for token in list(database["access_tokens"].values()):
        if token["username"] == username:
            del database["access_tokens"][token["token"]]

    write_database()

    return ({"message": "User deleted"}, 200)  # Http Status: "200 OK"

@app.route("/database", methods=["DELETE"])
def clear_database():
    global database
    database = make_empty_database()
    write_database()
    
    return ({"message": "Database cleared"}, 200)  # Http Status: "200 OK"

@app.route("/")
def get_website():
    return open(website_file_path).read()

def host_api():
    load_database()
    logging.basicConfig(level=logging.DEBUG)
    app.run(port=PORT, host=HOST)


if __name__ == "__main__":
    host_api()
