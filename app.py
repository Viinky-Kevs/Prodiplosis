from distutils.log import debug
from flask import Flask, render_template

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost/students'

@app.route('/')
def dash():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug = True)