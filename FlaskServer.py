from flask import Flask
from flask import request

app = Flask(__name__)


@app.route('/login')
def func():
    print(request.path)
    return 'Hello World'  # you should return a value that Flask interprets as a response


def show_info():
    print("Your IP is {}".format(request.environ["REMOTE_ADDR"]))
    print("Your Port is {}".format(request.environ["REMOTE_PORT"]))


@app.route('/')
def index():
    print(request.path)
    show_info()
    return '<h1>This is the home page<h1>' #will display the response in console when you make a request from the terminal
    #GET / HTPP/1.1


@app.route('/<path:path>')
def username(path):
    show_info()
    print(request.path)
    return 'Hello World'


@app.route('/profile/<int:id>')
def myId(id):
    return 'Your ID is {0}'.format(id)


if __name__ == '__main__':
    app.run('localhost', 8080, debug=True)
