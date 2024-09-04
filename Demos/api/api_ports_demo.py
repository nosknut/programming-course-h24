from flask import Flask

app2 = Flask(__name__)

@app2.route('/')
def hello_world():
    return 'Hello, World from app2!'

app2.run(port=3002, host="0.0.0.0")
