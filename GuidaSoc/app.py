import os
import logging
from flask import Flask, render_template

# Configurazione logging
logging.basicConfig(level=logging.DEBUG)

# Inizializzazione app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "chiave_temporanea_per_sviluppo")

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
