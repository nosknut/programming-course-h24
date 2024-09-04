# Programming Course H2024 Demos

This repository contains demos for the programming course H2024, and primarily focus on API's and databases. They mainly take the form of Python Jupyter notebooks.

## Tutorials

### NB

OpenAI, Spotify and "Spotify and ChatGPT" demos require you to have a `.env` file in each respective folder. The "Spotify and ChatGPT" demo describes this in more detail.

### SQLite

The [SQLite tutorial](Demos/sqlite/sqlite.ipynb) gives an introduction to relational databases by using the built-in SQLite file database in Python.

### Spotify and ChatGPT

The [Spotify and ChatGPT tutorial](Demos/spotify-chatgpt/spotify-gpt-demo.ipynb) demonstrates how to interact with the Spotify API and how to generate song recommendations using the ChatGPT API.

The contents of this demo has also been divided into two separate python demos that focus on each API individually. The [Spotify demo](Demos/spotify/spotify.py) and the [OpenAI demo](Demos/openai/openai.py).

#### NB

For the spotify demo to work, you must first scroll to the bottom of the file, and uncomment "host_endpoint()":

```py
if __name__ == "__main__":
    # recommend()
    host_auth_endpoint()
```

Then, run the code and must visit [http://localhost:8080/login](http://localhost:8080/login) in your browser to authenticate with Spotify. This will create the [spotify_token_data.json](spotify_token_data.json) file, which is required for the `recommend()` function to work. Once you have logged in and confirmed the file has been created, you you can stop the python script, comment out "host_auth_endpoint()", and run the file again.

```py
if __name__ == "__main__":
    recommend()
    # host_auth_endpoint()
```

### Ollama

The [Ollama tutorial](Demos/ollama/ollama.ipynb) demonstrates how to install and run a Large Language Model (LLM) like ChatGPT locally, and how to interact with the Ollama API to generate song lyrics. Because of hardware limitations, smaller LLM's like Facebook's llama3.1:8b are used in this demo.

### API

The [API tutorial](Demos/api/api.ipynb) demonstrates how to create and interact with a simple API using Flask. The demo also includes code for token-based authentication, and uses a JSON file as a database (to keep it separate from the SQLite tutorial).
