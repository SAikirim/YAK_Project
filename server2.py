from flask import Flask, request, jsonify, make_response
import pickle
#from tensorflow.keras.models import load_model


app = Flask(__name__)

#model = load_model("model.h5")
#model.predicit(x_test)

@app.route('/')
def hello_world():
    return 'Hello World!'

@app.route('/predict', methods=['GET','POST'])
def predict():
    data = pickle.loads(request.data)
    num1 = len(data)
    return make_response(jsonify({'result': num1}), 200)
    #return jsonify({'result': '1'})

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
