from flask import Flask, request, jsonify
import json

app = Flask(__name__)

# Example of POST endpoint
@app.route('/sum', methods=['POST'])
def calculate_sum():
    # Parse the body of the response as JSON
    data = request.get_json()
    
    print("Received POST request with body:")
    print(json.dumps(data, indent=4))
    
    a = data['a']
    b = data['b']
    c = data['c']
    
    result = a + b + c
    return {
        "sum": result
    }

# Example of GET endpoint using same path
@app.route('/sum')
def calculator_path_handler():
    a = int(request.args.get('a'))
    b = int(request.args.get('b'))
    c = int(request.args.get('c'))
    result = a + b + c
    
    return {
        "sum": result
    }


if __name__ == '__main__':
    app.run(port=3003, host="0.0.0.0")