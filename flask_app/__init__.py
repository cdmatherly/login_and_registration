from flask import Flask
app = Flask(__name__)
app.secret_key = 'keep it secret'
DATABASE = 'login_and_reg_db'