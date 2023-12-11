from flask import Flask, jsonify, render_template, redirect, url_for, request, session
from flask_limiter import Limiter, RateLimitExceeded
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
import os

# ========================================================================================================
#                          App configuration and database models
# ========================================================================================================

# >>>> Configuración de las variables de entorno >>>>

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')

db = SQLAlchemy(app)

limiter = Limiter(key_func=lambda: request.remote_addr, storage_uri="memory://")
limiter.init_app(app)

# >>>> Rate limit handler and call the funtion to log the activity for limit exceeded >>>>

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    ip = request.remote_addr
    route = request.endpoint if request.endpoint else request.url_rule
    action_details = f"/{route} - {ip}"

    user_id = current_user.user_id if current_user.is_authenticated else None

    exceeded_attempts_log = InventoryOperation(
        user_id=user_id,
        action_type="RateLimitExceeded",
        action_details=action_details,
        timestamp=datetime.now()
    )
    db.session.add(exceeded_attempts_log)
    db.session.commit()

    return jsonify({'error': 'Too many requests. Please try again later.'}), 429

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"
login_manager.init_app(app)

# >>>> User loader for the login manager >>>>

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# >>>> Database models >>>>

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    def get_id(self):
        return str(self.user_id)

    def has_permission(self, permission_id):
        user_roles = UserRole.query.filter_by(user_id=self.user_id).all()
        for user_role in user_roles:
            role_permissions = RolePermission.query.filter_by(role_id=user_role.role_id).all()
            for role_permission in role_permissions:
                permission = Permission.query.filter_by(permission_id=role_permission.permission_id).first()
                if permission.permission_id == permission_id:
                    return True
        return False

def serialize_user(user):
    return {
        'user_id': user.user_id,
        'username': user.username,
        'email': user.email,
        'created_at': user.created_at,
        'updated_at': user.updated_at
    }    

class InventoryOperation(db.Model):
    __tablename__ = 'inventory_operations'
    operation_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.product_id'))
    action_type = db.Column(db.String(50), nullable=False)
    action_details = db.Column(db.Text)
    timestamp = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())

def serialize_inventory_operation(inventory_operation):
    return {
        'operation_id': inventory_operation.operation_id,
        'user_id': inventory_operation.user_id,
        'product_id': inventory_operation.product_id,
        'action_type': inventory_operation.action_type,
        'action_details': inventory_operation.action_details,
        'timestamp': inventory_operation.timestamp
    }

class Category(db.Model):
    __tablename__ = 'categories'
    category_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

def serialize_category(category):
    return {
        'category_id': category.category_id,
        'name': category.name,
        'created_at': category.created_at,
        'updated_at': category.updated_at
    }

class Product(db.Model):
    __tablename__ = 'products'
    product_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.TEXT)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.category_id'))
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.DECIMAL(10, 2), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

def serialize_product(product):
    return {
        'product_id': product.product_id,
        'name': product.name,
        'description': product.description,
        'category_id': product.category_id,
        'quantity': product.quantity,
        'price': float(product.price),  
        'created_at': product.created_at,
        'updated_at': product.updated_at
    }

class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

def serialize_role(role):
    return {
        'role_id': role.role_id,
        'role_name': role.role_name,
        'created_at': role.created_at,
        'updated_at': role.updated_at
    }

class Permission(db.Model):
    __tablename__ = 'permissions'
    permission_id = db.Column(db.Integer, primary_key=True)
    permission_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

def serialize_permission(permission):
    return {
        'permission_id': permission.permission_id,
        'permission_name': permission.permission_name,
        'created_at': permission.created_at,
        'updated_at': permission.updated_at
    }

class UserRole(db.Model):
    __tablename__ = 'user_roles'
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'), primary_key=True)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

def serialize_user_role(user_role):
    return {
        'user_id': user_role.user_id,
        'role_id': user_role.role_id,
        'created_at': user_role.created_at,
        'updated_at': user_role.updated_at
    }

class RolePermission(db.Model):
    __tablename__ = 'role_permissions'
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.permission_id'), primary_key=True)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

def serialize_role_permission(role_permission):
    return {
        'role_id': role_permission.role_id,
        'permission_id': role_permission.permission_id,
        'created_at': role_permission.created_at,
        'updated_at': role_permission.updated_at
    }

# >>>> Log activity function for  all the routes >>>>

def log_activity(details, user_id=None, product_id=None, action_type=None, timestamp=None):
    
    ip = request.remote_addr
    
    inventory_operation = InventoryOperation(
        user_id=user_id,
        product_id=product_id,
        action_type=action_type+"-"+request.method,
        action_details=details+" "+ip,
        timestamp=timestamp
    )
    db.session.add(inventory_operation)
    db.session.commit()

# >>>> Log activity function for the limit exceeded >>>>    

def log_limit_exceeded(details, action_type, user_id=None, timestamp=None):
    ip = request.remote_addr

    exceeded_attempts_log = InventoryOperation(
        user_id=user_id,
        action_type=action_type,
        action_details=details + f" - ip: {ip}",
        timestamp=timestamp
    )
    db.session.add(exceeded_attempts_log)
    db.session.commit()

# >>>> Before request function to set the session lifetime >>>>

@app.before_request
def before_request():
    if current_user.is_authenticated:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=20)


# ========================================================================================================
#                          HOME ROUTE
# ========================================================================================================

# 🚀 Home route 🚀

@app.route('/')
@limiter.limit("10/minute")
@login_required
def home():

    return f'Welcome to the api!'

# 🚀 Not found routes 🚀

@app.errorhandler(404)
def page_not_found(e):
    return "Page not found", 404

# ========================================================================================================
#                          AUTHENTICATION ROUTES (LOGIN, LOGOUT, REGISTER)
# ========================================================================================================

# 🚀 Register route 🚀

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("2/ 30 minutes")
def register():
    user_id = None
    action_type = "Auth-/register"
    
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            result_message = "Error - Username already exists - user:"
            return result_message, 401

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            result_message = "Error - Email already exists - user:"
            return result_message, 401

        new_user = User(username=username, email=email, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()

        user_role = Role.query.filter_by(role_name='user').first()
        user_role_relation = UserRole(user_id=new_user.user_id, role_id=user_role.role_id)
        db.session.add(user_role_relation)
        db.session.commit()

        login_user(new_user)

        result_message = "Success - IP:"
        user_id = current_user.user_id

        return result_message, 200

    else:
        result_message = "Success - IP:"

    log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=user_id)

    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        return "Login successful"

# 🚀 Login route 🚀

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10/ 15 minutes")
def login():
    user_id = None
    action_type = "Auth-/login"
    
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            result_message = "Success - IP:"
            user_id = current_user.user_id
        else:
            result_message = f"Error - Invalid Credentials - user:{username} - ip:"
            log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=user_id)
            return "Invalid credentials", 401
    else:
        result_message = "Sucess - IP:"
    log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=user_id)

    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        return "Login successful"
    
# 🚀 Logout route 🚀

@app.route('/logout')   
@login_required
def logout():
    user_id = current_user.user_id
    action_type = "Auth-/logout"
    result_message = "Success - IP:"
    log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=user_id)
    logout_user()
    return redirect(url_for('home'))

# ========================================================================================================
#                          USER ROUTES
# ========================================================================================================

# 🚀 Get Profile route 🚀

@app.route('/profile')
@login_required
@limiter.limit("10/minute")
def get_profile():
    user_id = current_user.user_id
    action_type = "Users-/profile"
    result_message = "Success - IP:"
    log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=user_id)
    
    return f'Hello, {current_user.username, current_user.email}!'

# 🚀 1) GET - View All Users 🚀

@app.route('/users')
@login_required
@limiter.limit("10/minute")
def get_users():
    if current_user.has_permission(1):
        users = User.query.all()
        serialized_users = [serialize_user(user) for user in users]
        action_type = "Users-/users"
        result_message = "Success - IP:"
        log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=current_user.user_id)
        return jsonify(serialized_users)
    else:
        result_message = "Error - Unauthorized access attempt - Permission:1 - IP:"
        log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=current_user.user_id)
        return "You don't have permission to perform this action"
    
# 🚀 2) GET - View User by ID 🚀

@app.route('/users/<int:user_id>')
@login_required
@limiter.limit("10/minute")
def get_user(user_id):
    if current_user.has_permission(2):
        user = User.query.filter_by(user_id=user_id).first()
        if user:
            serialized_user = serialize_user(user)
            action_type = "Users-/users/<int:user_id>"
            result_message = "Success - IP:"
            log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=current_user.user_id)
            return jsonify(serialized_user)
        else:
            result_message = "Error - User not found - IP:"
            log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=current_user.user_id)
            return "User not found"
    else:
        result_message = "Error - Unauthorized access attempt - Permission:2 - IP:"
        log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=current_user.user_id)
        return "You don't have permission to perform this action"
    
# 🚀 3) DELETE - Delete User by ID 🚀    

@app.route('/users/<int:user_id>', methods=['DELETE'])
@login_required
@limiter.limit("10/minute")
def remove_user(user_id):
    if current_user.has_permission(3):
        user = User.query.filter_by(user_id=user_id).first()
        db.session.delete(user)
        db.session.commit()
        action_type = "Users-/users/<int:user_id>"
        result_message = "Success - IP:"
        log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=current_user.user_id)
        return "User removed successfully"
    else:
        result_message = "Error - Unauthorized access attempt - Permission:3 - IP:"
        log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=current_user.user_id)
        return "You don't have permission to perform this action"

# 🚀 4) PUT - Update User by ID 🚀

@app.route('/users/<int:user_id>', methods=['PUT'])
@login_required
@limiter.limit("10/minute")
def update_user(user_id):
    if current_user.has_permission(4):
        user = User.query.filter_by(user_id=user_id).first()
        user.username = request.form['username']
        user.email = request.form['email']
        db.session.commit()
        action_type = "Users-/users/<int:user_id>"
        result_message = "Success - IP:"
        log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=current_user.user_id)
        return "User updated successfully"
    else:
        result_message = "Error - Unauthorized access attempt - Permission:4 - IP:"
        log_activity(result_message, action_type=f"{action_type}", timestamp=datetime.now(), user_id=current_user.user_id)
        return "You don't have permission to perform this action"
    
#========================================================================================================
#                          PRODUCT ROUTES
#========================================================================================================

# 🚀 5) GET - View All Products 🚀

@app.route('/products')
@login_required
@limiter.limit("10/minute")
def get_products():
    try:
        if current_user.has_permission(5):
            products = Product.query.all()
            serialized_products = [serialize_product(product) for product in products]
            log_activity("Success - Access to products - IP:", action_type="Products-/products", user_id=current_user.user_id)
            return jsonify(serialized_products)
        
        else:
            log_activity("Unauthorized access attempt - Permission:5 - IP:", action_type="Products-/products", user_id=current_user.user_id)
            return "You don't have permission to perform this action", 401
        
    except Exception as e:
        log_activity(f"Error - {str(e)} - IP:", action_type="Products-/products", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# 🚀 6) GET - View Product by ID 🚀
    
@app.route('/product/<int:product_id>')
@login_required
@limiter.limit("10/minute")
def get_product(product_id):
    try:
        if current_user.has_permission(6):
            product = Product.query.filter_by(product_id=product_id).first()
            if product:
                serialized_product = serialize_product(product)
                log_activity("Success - Access to product - IP:", action_type=f"Products-/product/{product_id}", user_id=current_user.user_id)
                return jsonify(serialized_product), 200
            else:
                log_activity("Error - Product not found - IP:", action_type=f"Products-/product/{product_id}", user_id=current_user.user_id)
                return "Product not found", 404
        
        else:
            log_activity("Unauthorized access attempt - Permission:5 - IP:", action_type=f"Products-/product/{product_id}", user_id=current_user.user_id)
            return "You don't have permission to perform this action", 401
        
    except Exception as e:
        log_activity(f"Error - {str(e)} - IP:", action_type=f"Products-/product/{product_id}", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# 7) POST -Add Product 🚀

@app.route('/product', methods=['POST'])
@login_required
@limiter.limit("10/minute")
def add_product():
    try:
        if current_user.has_permission(7):
            name = request.form['name']
            description = request.form['description']
            category_id = request.form['category_id']
            quantity = request.form['quantity']
            price = request.form['price']
            
            new_product = Product(name=name, description=description, category_id=category_id, quantity=quantity, price=price)
            db.session.add(new_product)
            db.session.commit()
            
            log_activity(f"Success - Product added {name}", action_type="Products-/product", user_id=current_user.user_id)
            return "Product added successfully", 200
        
        else:
            log_activity("Unauthorized access attempt - Permission:7 - IP:", action_type="Products-/product", user_id=current_user.user_id)
            return "You don't have permission to perform this action", 401
        
    except Exception as e:
        log_activity(f"Error - {str(e)} - IP:", action_type="Products-/product", user_id=current_user.user_id)
        return "An error occurred while processing the request"
            
# 🚀8) DELETE - Delete Product by ID 🚀
    
@app.route('/products/<int:product_id>', methods=['DELETE'])
@login_required
@limiter.limit("10/minute")
def remove_product(product_id):
    try:
        if current_user.has_permission(8):
            product = Product.query.filter_by(product_id=product_id).first()
            db.session.delete(product)
            db.session.commit()
            
            log_activity("Success - Product removed", action_type=f"Products-/product/{product_id}", user_id=current_user.user_id)
            return "Product removed successfully"
        
        else:
            log_activity("Unauthorized access attempt - Permission:8 - IP:", action_type=f"Products-/product/{product_id}", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)} - IP:", action_type=f"Products-/product/{product_id}", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# 🚀9) PUT - Update Product by ID 🚀

@app.route('/product/<int:product_id>', methods=['PUT'])
@login_required
@limiter.limit("10/minute")
def update_product(product_id):
    try:
        if current_user.has_permission(9):
            product = Product.query.filter_by(product_id=product_id).first()
            product.name = request.form['name']
            product.description = request.form['description']
            product.category_id = request.form['category_id']
            product.quantity = request.form['quantity']
            product.price = request.form['price']
            db.session.commit()
            
            log_activity("Success - Product updated", action_type= f"Products-/product/{product_id}", user_id=current_user.user_id)
            return "Product updated successfully", 200
        
        else:
            log_activity("Unauthorized access attempt - Permission:9 - IP:",action_type= f"Products-/product/{product_id}", user_id=current_user.user_id)
            return "You don't have permission to perform this action", 401
        
    except Exception as e:
        log_activity(f"Error - {str(e)} - IP:", action_type=f"Products-/product/{product_id}", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# ========================================================================================================
#                          CATEGORIES ROUTES
# ========================================================================================================

# 🚀 10) GET - View All Categories 🚀

@app.route('/categories')
@login_required
@limiter.limit("10/minute")
def get_categories():
    try:
        if current_user.has_permission(10):
            categories = Category.query.all()
            serialized_categories = [serialize_category(category) for category in categories]
            log_activity("Success - Access to categories", action_type="Categories-/categories", user_id=current_user.user_id)
            return jsonify(serialized_categories)
        
        else:
            log_activity("Unauthorized access attempt - Permission:10 - IP:", action_type="Categories-/categories", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="Categories-/categories", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# 🚀 11) GET - View Category by ID 🚀
    
@app.route('/category/<int:category_id>')
@login_required
@limiter.limit("10/minute")
def get_category(category_id):
    try:
        if current_user.has_permission(11):
            category = Category.query.filter_by(category_id=category_id).first()
            if category:
                serialized_category = serialize_category(category)
                log_activity("Success - Access to category", action_type="Categories-/category/{category_id}", user_id=current_user.user_id)
                return jsonify(serialized_category)
            else:
                log_activity("Error - Category not found", action_type="Categories-/category/{category_id}", user_id=current_user.user_id)
                return "Category not found"
        
        else:
            log_activity("Unauthorized access attempt - Permission:11 - IP:", action_type="Categories-/category/{category_id}", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="Categories-/category/{category_id}", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# 🚀 12) POST - Add Category 🚀

@app.route('/categories', methods=['POST'])
@login_required
@limiter.limit("10/minute")
def add_category():
    try:
        if current_user.has_permission(12):
            name = request.form['name']
            
            new_category = Category(name=name)
            db.session.add(new_category)
            db.session.commit()
            
            log_activity("Success - Category added", action_type="Categories-/categories", user_id=current_user.user_id)
            return "Category added successfully"
        
        else:
            log_activity("Unauthorized access attempt - Permission:12 - IP:", action_type="Categories-/categories", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="Categories-/categories", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# 🚀 13) DELETE - Delete Category by ID 🚀

@app.route('/categories/<int:category_id>', methods=['DELETE'])
@login_required
@limiter.limit("10/minute")
def remove_category(category_id):
    try:
        if current_user.has_permission(13):
            category = Category.query.filter_by(category_id=category_id).first()
            db.session.delete(category)
            db.session.commit()
            
            log_activity("Success - Category removed", action_type="Categories-/categories/<int:category_id>", user_id=current_user.user_id)
            return "Category removed successfully"
        
        else:
            log_activity("Unauthorized access attempt - Permission:13 - IP:", action_type="Categories-/categories/<int:category_id>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="Categories-/categories/<int:category_id>", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# 🚀 14) PUT - Update Category by ID 🚀

@app.route('/categories/<int:category_id>', methods=['PUT'])
@login_required
@limiter.limit("10/minute")
def update_category(category_id):
    try:
        if current_user.has_permission(14):
            category = Category.query.filter_by(category_id=category_id).first()
            category.name = request.form['name']
            db.session.commit()
            
            log_activity("Success - Category updated", action_type="Categories-/categories/<int:category_id>", user_id=current_user.user_id)
            return "Category updated successfully"
        
        else:
            log_activity("Unauthorized access attempt - Permission:14 - IP:", action_type="Categories-/categories/<int:category_id>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="Categories-/categories/<int:category_id>", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# ========================================================================================================
#                          ROLES ROUTES
# ========================================================================================================

# 🚀 15) GET - View All Roles 🚀

@app.route('/roles')
@login_required
@limiter.limit("10/minute")
def get_roles():
    try:
        if current_user.has_permission(15):
            roles = Role.query.all()
            serialized_roles = [serialize_role(role) for role in roles]
            log_activity("Success - Access to roles", action_type="Roles-/roles", user_id=current_user.user_id)
            return jsonify(serialized_roles)
        
        else:
            log_activity("Unauthorized access attempt - Permission:14 - IP:", action_type="Roles-/roles", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="Roles-/roles", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# 🚀 16) GET - View Role by ID 🚀
    
@app.route('/roles/<int:role_id>')
@login_required
@limiter.limit("10/minute")
def get_role(role_id):
    try:
        if current_user.has_permission(16):
            role = Role.query.filter_by(role_id=role_id).first()
            serialized_role = serialize_role(role)
            log_activity("Success - Access to role", action_type="Roles-/roles/<int:role_id>", user_id=current_user.user_id)
            return jsonify(serialized_role)
        
        else:
            log_activity("Unauthorized access attempt - Permission:16 - IP:", action_type="Roles-/roles/<int:role_id>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="Roles-/roles/<int:role_id>", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# ========================================================================================================
#                          PERMISSIONS ROUTES
# ========================================================================================================

# 🚀 17) GET - View All Permissions 🚀

@app.route('/permissions')
@login_required
@limiter.limit("10/minute")
def get_permissions():
    try:
        if current_user.has_permission(17):
            permissions = Permission.query.all()
            serialized_permissions = [serialize_permission(permission) for permission in permissions]
            log_activity("Success - Access to permissions", action_type="Permissions-/permissions", user_id=current_user.user_id)
            return jsonify(serialized_permissions)
        
        else:
            log_activity("Unauthorized access attempt - Permission:17 - IP:", action_type="Permissions-/permissions", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="Permissions-/permissions", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# 🚀 18) GET - View Permission by ID 🚀
    
@app.route('/permissions/<int:permission_id>')
@login_required
@limiter.limit("10/minute")
def get_permission(permission_id):
    try:
        if current_user.has_permission(18):
            permission = Permission.query.filter_by(permission_id=permission_id).first()
            serialized_permission = serialize_permission(permission)
            log_activity("Success - Access to permission", action_type="Permissions-/permissions/<int:permission_id>", user_id=current_user.user_id)
            return jsonify(serialized_permission)
        
        else:
            log_activity("Unauthorized access attempt - Permission:18 - IP:", action_type="Permissions-/permissions/<int:permission_id>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="Permissions-/permissions/<int:permission_id>", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
    
# ========================================================================================================
#                          USER_ROLES ROUTES
# ========================================================================================================

# 🚀 19) GET - View All User Roles 🚀

@app.route('/user_roles')
@login_required
@limiter.limit("10/minute")
def get_user_roles():
    try:
        if current_user.has_permission(19):
            user_roles = UserRole.query.all()
            serialized_user_roles = [serialize_user_role(user_role) for user_role in user_roles]
            log_activity("Success - Access to user_roles", action_type="UserRoles-/user_roles", user_id=current_user.user_id)
            return jsonify(serialized_user_roles)
        
        else:
            log_activity("Unauthorized access attempt - Permission:19 - IP:", action_type="UserRoles-/user_roles", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="UserRoles-/user_roles", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# 🚀 20) GET - View User Role by USER ID 🚀
    
@app.route('/user_roles/<int:user_id>')
@login_required
@limiter.limit("10/minute")
def get_user_role_user(user_id):
    try:
        if current_user.has_permission(20):
            user_roles = UserRole.query.filter_by(user_id=user_id).all()
            serialized_user_roles = [serialize_user_role(user_role) for user_role in user_roles]
            log_activity("Success - Access to user_role", action_type="UserRoles-/user_roles/<int:user_id>", user_id=current_user.user_id)
            return jsonify(serialized_user_roles)
        
        else:
            log_activity("Unauthorized access attempt - Permission:20 - IP:", action_type="UserRoles-/user_roles/<int:user_id>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="UserRoles-/user_roles/<int:user_id>", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# 🚀 21) GET - View User Role by ROLE ID 🚀

@app.route('/user_roles/<int:role_id>')
@login_required
@limiter.limit("10/minute")
def get_user_role_id(role_id):
    try:
        if current_user.has_permission(21):
            user_roles = UserRole.query.filter_by(role_id=role_id).all()
            serialized_user_roles = [serialize_user_role(user_role) for user_role in user_roles]
            log_activity("Success - Access to user_role", action_type="UserRoles-/user_roles/<int:role_id>", user_id=current_user.user_id)
            return jsonify(serialized_user_roles)
        
        else:
            log_activity("Unauthorized access attempt - Permission:21 - IP:", action_type="UserRoles-/user_roles/<int:role_id>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="UserRoles-/user_roles/<int:role_id>", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# 🚀 22) POST - Add User Role 🚀

@app.route('/user_roles', methods=['POST'])
@login_required
@limiter.limit("10/minute")
def add_user_role():
    try:
        if current_user.has_permission(22):
            user_id = request.form['user_id']
            role_id = request.form['role_id']
            
            new_user_role = UserRole(user_id=user_id, role_id=role_id)
            db.session.add(new_user_role)
            db.session.commit()
            
            log_activity("Success - User role added", action_type="UserRoles-/user_roles", user_id=current_user.user_id)
            return "User role added successfully"
        
        else:
            log_activity("Unauthorized access attempt - Permission:22 - IP:", action_type="UserRoles-/user_roles", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="UserRoles-/user_roles", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# 🚀 23) DELETE - Delete User Role by USER ID and ROLE ID 🚀

@app.route('/user_roles/<int:user_id>/<int:role_id>', methods=['DELETE'])
@login_required
@limiter.limit("10/minute")
def remove_user_role(user_id, role_id):
    try:
        if current_user.has_permission(23):
            user_role = UserRole.query.filter_by(user_id=user_id, role_id=role_id).first()
            db.session.delete(user_role)
            db.session.commit()
            
            log_activity("Success - User role removed", action_type="UserRoles-/user_roles/<int:user_id>/<int:role_id>", user_id=current_user.user_id)
            return "User role removed successfully"
        
        else:
            log_activity("Unauthorized access attempt - Permission:23 - IP:", action_type="UserRoles-/user_roles/<int:user_id>/<int:role_id>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="UserRoles-/user_roles/<int:user_id>/<int:role_id>", user_id=current_user.user_id)
        return "An error occurred while processing the request"
        
# ========================================================================================================
#                          ROLE_PERMISSIONS ROUTES
# ========================================================================================================

# 🚀 24) GET - View permission list specif role 🚀

@app.route('/role_permissions/<int:role_id>')
@login_required
@limiter.limit("10/minute")
def get_role_permissions(role_id):
    try:
        if current_user.has_permission(24):
            role_permissions = RolePermission.query.filter_by(role_id=role_id).all()
            serialized_role_permissions = [serialize_role_permission(role_permission) for role_permission in role_permissions]
            log_activity("Success - Access to role_permissions", action_type="RolePermissions-/role_permissions/<int:role_id>", user_id=current_user.user_id)
            return jsonify(serialized_role_permissions)
        
        else:
            log_activity("Unauthorized access attempt - Permission:24 - IP:", action_type="RolePermissions-/role_permissions/<int:role_id>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="RolePermissions-/role_permissions/<int:role_id>", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# 🚀 25) POST - Add Role Permission 🚀

@app.route('/role_permissions', methods=['POST'])
@login_required
@limiter.limit("10/minute")
def add_role_permission():
    try:
        if current_user.has_permission(25):
            role_id = request.form['role_id']
            permission_id = request.form['permission_id']
            
            new_role_permission = RolePermission(role_id=role_id, permission_id=permission_id)
            db.session.add(new_role_permission)
            db.session.commit()
            
            log_activity("Success - Role permission added", action_type="RolePermissions-/role_permissions", user_id=current_user.user_id)
            return "Role permission added successfully"
        
        else:
            log_activity("Unauthorized access attempt Permission:25 - IP:", action_type="RolePermissions-/role_permissions", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="RolePermissions-/role_permissions", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# 🚀 26) DELETE - Delete Role Permission ROLE ID - PERMISSION ID 🚀

@app.route('/role_permissions/<int:role_id>/<int:permission_id>', methods=['DELETE'])
@login_required
@limiter.limit("10/minute")
def remove_role_permission(role_id, permission_id):
    try:
        if current_user.has_permission(23):
            role_permission = RolePermission.query.filter_by(role_id=role_id, permission_id=permission_id).first()
            db.session.delete(role_permission)
            db.session.commit()
            
            log_activity("Success - Role permission removed", action_type="RolePermissions-/role_permissions/<int:role_id>/<int:permission_id>", user_id=current_user.user_id)
            return "Role permission removed successfully"
        
        else:
            log_activity("Unauthorized access attempt Permission:26 - IP:", action_type="RolePermissions-/role_permissions/<int:role_id>/<int:permission_id>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="RolePermissions-/role_permissions/<int:role_id>/<int:permission_id>", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# ========================================================================================================
#                          INVENTORY_OPERATIONS ROUTES
# ========================================================================================================

# 🚀 27) GET - View Inventory Operations page 🚀

@app.route('/inventory_operations/<int:page>')
@login_required
@limiter.limit("10/minute")
def get_inventory_operations(page):
    try:
        if current_user.has_permission(27):
            inventory_operations = InventoryOperation.query.paginate(page=page, per_page=100)
            serialized_inventory_operations = [serialize_inventory_operation(inventory_operation) for inventory_operation in inventory_operations.items]
            log_activity("Success - Access to inventory_operations", action_type="InventoryOperations-/inventory_operations/<int:page>", user_id=current_user.user_id)
            return jsonify(serialized_inventory_operations)
        
        else:
            log_activity("Unauthorized access attempt Permission:27 - IP:", action_type="InventoryOperations-/inventory_operations/<int:page>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="InventoryOperations-/inventory_operations/<int:page>", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# 🚀 28) GET - View Inventory Operations by USER ID 🚀

@app.route('/inventory_operations/<int:user_id>/<int:page>')
@login_required
@limiter.limit("10/minute")
def get_inventory_operations_by_user(user_id, page):
    try:
        if current_user.has_permission(28):
            inventory_operations = InventoryOperation.query.filter_by(user_id=user_id).paginate(page=page, per_page=100)
            serialized_inventory_operations = [serialize_inventory_operation(inventory_operation) for inventory_operation in inventory_operations.items]
            log_activity("Success - Access to inventory_operations", action_type="InventoryOperations-/inventory_operations/<int:user_id>/<int:page>", user_id=current_user.user_id)
            return jsonify(serialized_inventory_operations)
        
        else:
            log_activity("Unauthorized access attempt Permission:28 - IP:", action_type="InventoryOperations-/inventory_operations/<int:user_id>/<int:page>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="InventoryOperations-/inventory_operations/<int:user_id>/<int:page>", user_id=current_user.user_id)
        return "An error occurred while processing the request"

# 🚀 29) GET - View Inventory Operations by PRODUCT ID 🚀

@app.route('/inventory_operations/{product_id}/<int:page>')
@login_required
@limiter.limit("10/minute")
def get_inventory_operations_by_product(product_id, page):
    try:
        if current_user.has_permission(29):
            inventory_operations = InventoryOperation.query.filter_by(product_id=product_id).paginate(page=page, per_page=100)
            serialized_inventory_operations = [serialize_inventory_operation(inventory_operation) for inventory_operation in inventory_operations.items]
            log_activity("Success - Access to inventory_operations", action_type="InventoryOperations-/inventory_operations/{product_id}/<int:page>", user_id=current_user.user_id)
            return jsonify(serialized_inventory_operations)
        
        else:
            log_activity("Unauthorized access attempt Permission:29 - IP:", action_type="InventoryOperations-/inventory_operations/{product_id}/<int:page>", user_id=current_user.user_id)
            return "You don't have permission to perform this action"
        
    except Exception as e:
        log_activity(f"Error - {str(e)}", action_type="InventoryOperations-/inventory_operations/{product_id}/<int:page>", user_id=current_user.user_id)
        return "An error occurred while processing the request"
    
# 🚀 30) Get - View inventory operation for type based in the action type column 🚀

@app.route('/inventory_operations/<string:action_type>/<int:page>')
@login_required
@limiter.limit("10/minute")
def get_inventory_operations_by_action_type(action_type, page):
    valid_action_types = ['Auth', 'Users', 'Products', 'Categories', 'Roles', 'Permissions', 'UserRoles', 'RolePermissions', 'InventoryOperations']
    if action_type in valid_action_types:
        try:
            if current_user.has_permission(30):
                inventory_operations = InventoryOperation.query.filter_by(action_type=action_type.split("-/")[0]).paginate(page=page, per_page=100)
                serialized_inventory_operations = [serialize_inventory_operation(inventory_operation) for inventory_operation in inventory_operations.items]
                log_activity("Success - Access to inventory_operations", action_type="InventoryOperations-/inventory_operations/<string:action_type>/<int:page>", user_id=current_user.user_id)
                return jsonify(serialized_inventory_operations)
            
            else:
                log_activity("Unauthorized access attempt Permission:30 - IP:", action_type="InventoryOperations-/inventory_operations/<string:action_type>/<int:page>", user_id=current_user.user_id)
                return "You don't have permission to perform this action"
            
        except Exception as e:
            log_activity(f"Error - {str(e)}", action_type="InventoryOperations-/inventory_operations/<string:action_type>/<int:page>", user_id=current_user.user_id)
            return "An error occurred while processing the request"
    else:
        log_activity("Error - Invalid action type", action_type="InventoryOperations-/inventory_operations/<string:action_type>/<int:page>", user_id=current_user.user_id)
        return "Invalid action type: the action type must be one of the following: Auth, Users, Products, Categories, Roles, Permissions, UserRoles, RolePermissions, InventoryOperations"
    

# ========================================================================================================
#                          Launch app
# ========================================================================================================

if __name__ == "__main__":
    app.run( port=5522,host='0.0.0.0', debug=True, ssl_context='adhoc')
