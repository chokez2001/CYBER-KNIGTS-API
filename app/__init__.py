from flask import Flask, jsonify, request
from flask_limiter import Limiter
from supabase import create_client
from dotenv import load_dotenv
import os


load_dotenv()

app = Flask(__name__)

supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

supabase = create_client(supabase_url, supabase_key)

limiter = Limiter(key_func=lambda: request.remote_addr)
limiter.init_app(app)

@app.route("/")
@limiter.limit("10/minute")
def index():
    return "Welcome to Cyber Knigts Flask API"

# Ruta para registro de usuario
@app.route("/register", methods=["POST"])
@limiter.limit("5/minute")
def register_user():
    data = request.get_json()
    email = data["email"]
    password = data["password"]
  
    
    user = supabase.auth.sign_up( {
    "email": email,
    "password": password,
    "options": {
      "data": {
        "role": 'ADMIN',
      }
    }
  })
    
    return jsonify({"message": "User registered successfully"}), 201


# Ruta para inicio de sesión
@app.route("/login", methods=["POST"])
def login_user():
    data = request.get_json()

    try:
        # Inicia sesión con Supabase
        auth_response = supabase.auth.sign_in_with_password(data)
        token = auth_response.session.access_token
        
        # Obtiene el ID del usuario
        user_id = auth_response.user.id if hasattr(auth_response, "user") else None

        # Crea una respuesta JSON
        response = jsonify({"message": "User logged in successfully", "user_id": user_id})

        # Almacena el token en una cookie segura
        response.set_cookie("session_token", token, httponly=True, secure=True, samesite="None")

        return response, 200

    except Exception as e:
        # Captura y maneja cualquier excepción que pueda ocurrir
        print(f"Error during login: {e}")

        # Verifica si el error es debido a credenciales inválidas
        if "Invalid login credentials" in str(e):
            return jsonify({"message": "Invalid login credentials"}), 400
        else:
            return jsonify({"message": "An error occurred during login"}), 500


#Ruta para obtener el token de sesión
@app.route("/token", methods=["GET"])
@limiter.limit("10/minute")
def get_token():
    try:
        token_response = supabase.auth.get_session()
       
        if token_response != None:
            print(token_response)
            return jsonify(token_response.access_token), 200
        else:
            return jsonify({"message": "No token found"}), 404
        
    except Exception as e:
        print(f"----Error getting token----: {str(e)}")
        return jsonify({"message": "An error occurred while getting token"}), 500


  
# Ruta para obtener el usuario
@app.route("/user", methods=["GET"])
@limiter.limit("10/minute")
def get_user(): 

    try:
        token = request.cookies.get("session_token")

        if not token:
            return jsonify({"message": "No token found"}), 401
        else:
            user_response = supabase.auth.get_user(token)
            print(user_response)

            user_data = user_response.user.identities[0].identity_data if hasattr(user_response, "user") else None  
      
            return jsonify(user_data), 200
        
    except Exception as e:
        print(f"----Error getting user----: {str(e)}")
        return jsonify({"message": "An error occurred while getting user information"}), 500


#Ruta para obtener todos los usuarios
@app.route("/users", methods=["GET"])
@limiter.limit("10/minute")
def get_users():
    try:
        users_response = supabase.table("users").select('*').execute()
        print(users_response)

        if users_response:
            return jsonify(users_response.data), 200
    
    except Exception as e:
        print(f"----Error getting users----: {str(e)}")
        return jsonify({"message": "An error occurred while getting users"}), 500



# Ruta para obtener todos los productos
@app.route("/products", methods=["GET"])
@limiter.limit("10/minute")
def get_products():
    try:
        products_response = supabase.table("products").select('*').execute()
        

        if products_response:
            return jsonify(products_response.data), 200
    
    except Exception as e:
        print(f"----Error getting products----: {str(e)}")
        return jsonify({"message": "An error occurred while getting products"}), 500

        
    
# Ruta para añadir productos
@app.route("/products", methods=["POST"])
@limiter.limit("10/minute")
def add_products():
    try:
        data = request.get_json()
        name = data["name"]
        description = data["description"]
       

        products_response = supabase.table("products").insert([{"name":name,"description":description}]).execute()

        if products_response:
            return jsonify({"message": "Product added successfully"}), 200
    except Exception as e:
        print(f"----Error adding products----: {str(e)}")
        return jsonify({"message": "An error occurred while adding products"}), 500
    
# Ruta para obtener un producto 
@app.route("/products/<int:id>", methods=["GET"])
@limiter.limit("10/minute")
def get_product(id):
    try:
        product_response = supabase.table("products").select('*').eq('id', id).execute()

        if product_response:
            return jsonify(product_response.data), 200
    
    except Exception as e:
        print(f"----Error getting product----: {str(e)}")
        return jsonify({"message": "An error occurred while getting product"}), 500
    
