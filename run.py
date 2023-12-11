from app import app
from config.settings import Config

if __name__ == "__main__":
    app.run(debug=True,
            host='0.0.0.0',
            port=Config.port)