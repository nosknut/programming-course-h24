# Run this file using one of the following commands:
# Windows PowerShell:
# $env:PORT=3001; $env:HOST="0.0.0.0"; python Demos/api/env_demo.py
# Mac Terminal:
# PORT=3001 HOST="0.0.0.0" python Demos/api/env_demo.py
# Linux Terminal:
# export PORT=3001 HOST="0.0.0.0" python Demos/api/env_demo.py

import os

# Access the environment variables
port_number = os.getenv("PORT")
host = os.getenv("HOST")

print("The value of the PORT env variable is: ", port_number)
print("The value of the HOST env variable is: ", host)