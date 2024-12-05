from datetime import datetime, timedelta
import os
import jwt
from flask import Flask, jsonify, request, render_template
import peewee
from peewee import PostgresqlDatabase
import bcrypt
import secrets


app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    secret_key = secrets.token_hex(16) # Генерируем 128-битный ключ (16 байт * 2 hex символа/байт)


app.config['SECRET_KEY'] = secret_key
app.config['JWT_EXPIRY_MINUTES'] = 60 # Добавьте эту строку! Время жизни токена в минутах
# Конфигурация базы данных
DATABASE_NAME = "postgres"  # Используйте имя вашей базы данных
DATABASE_USER = "postgres"  # Используйте имя пользователя вашей базы данных
DATABASE_PASSWORD = "admin"  # Используйте ваш пароль
DATABASE_HOST = "127.0.0.1"
DATABASE_PORT = 5432

db = PostgresqlDatabase(
    DATABASE_NAME,
    user=DATABASE_USER,
    password=DATABASE_PASSWORD,
    host=DATABASE_HOST,
    port=DATABASE_PORT
)


class User(peewee.Model):
    username = peewee.CharField(unique=True, max_length=80)
    password_hash = peewee.BlobField()

    class Meta:
        database = db
        db_table = 'users'


def connect_db():
    try:
        db.connect()
        print("Успешно подключились к базе данных!")
        return True
    except Exception as e:
        print(f"Ошибка подключения к базе данных: {e}")
        return False


def create_user_table():
    if not User.table_exists():
        db.create_tables([User])
        print("Таблица 'users' создана успешно!")
    else:
        print("Таблица 'users' уже существует.")





def generate_jwt(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(minutes=app.config['JWT_EXPIRY_MINUTES'])
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed # Не нужно преобразовывать в bytes здесь

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        if not request.is_json:
            return jsonify({'message': 'Content-Type должен быть application/json'}), 415

        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"message": "Имя пользователя и пароль обязательны!"}), 400

        hashed_password = hash_password(password)

        with db.atomic():
            try:
                User.create(username=username, password_hash=hashed_password)  # Храним bytes напрямую
                return jsonify({"message": "Пользователь успешно зарегистрирован!"}), 201
            except peewee.IntegrityError:
                return jsonify({"message": "Пользователь с таким именем уже существует!"}), 409

    except Exception as e:
        print(f"Ошибка во время регистрации: {e}")
        return jsonify({"message": "Произошла непредвиденная ошибка"}), 500


@app.route('/login', methods=['GET'])
def show_login():
    return render_template('auth.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        if not request.is_json:
            return jsonify({'message': 'Content-Type должен быть application/json'}), 415

        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"message": "Имя пользователя и пароль обязательны!"}), 400

        user = User.get_or_none(User.username == username)
        if user is None:
            return jsonify({"message": "Неверное имя пользователя или пароль!"}), 401

            # ПРАВИЛЬНО: Преобразуем в bytes только при извлечении из базы данных
        hashed_password_bytes = bytes(user.password_hash)

        if not verify_password(password, hashed_password_bytes):
            return jsonify({"message": "Неверное имя пользователя или пароль!"}), 401

        token = generate_jwt(user.id)
        return jsonify({"message": "Успешный вход в систему!", "token": token}), 200

    except Exception as e:
        print(f"Ошибка во время входа: {e}")
        return jsonify({"message": "Произошла непредвиденная ошибка"}), 500

@app.route('/protected', methods=['GET'])
def protected():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"message": "Токен отсутствует"}), 401

        token = auth_header.split(" ")[1] # Удаляем "Bearer "
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = payload['user_id']
        return jsonify({"message": f"Защищенный ресурс доступен. User ID: {user_id}"}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Токен истек"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Неверный токен"}), 401
    except Exception as e:
        print(f"Ошибка при проверке токена: {e}")
        return jsonify({"message": "Произошла непредвиденная ошибка"}), 500

# REST API для пользователей
@app.route('/api/users', methods=['GET'])
def get_users():
    users_list = [{"id": user.id, "username": user.username} for user in User.select()]
    return jsonify(users_list)


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user = User.get_or_none(User.id == user_id)
    if user is None:
        return jsonify({'message': 'Пользователь не найден'}), 404
    return jsonify({"id": user.id, "username": user.username})


@app.route('/api/users', methods=['POST'])
def create_user_api():
    try:
        if not request.is_json:
            return jsonify({'message': 'Content-Type должен быть application/json'}), 415

        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"message": "Имя пользователя и пароль обязательны!"}), 400

        hashed_password = hash_password(password)

        with db.atomic():
            try:
                User.create(username=username, password_hash=hashed_password)
                return jsonify({"message": "Пользователь успешно создан!"}), 201
            except peewee.IntegrityError:
                return jsonify({"message": "Пользователь с таким именем уже существует!"}), 409

    except Exception as e:
        print(f"Ошибка при создании пользователя: {e}")
        return jsonify({"message": "Произошла непредвиденная ошибка"}), 500


@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user_api(user_id):
    try:
        user = User.get_or_none(User.id == user_id)
        if user is None:
            return jsonify({'message': 'Пользователь не найден'}), 404

        data = request.json
        username = data.get('username')
        password = data.get('password')

        if username:
            user.username = username
        if password:
            user.password_hash = hash_password(password)

        user.save()
        return jsonify({"message": "Пользователь успешно обновлен!"})

    except Exception as e:
        print(f"Ошибка при обновлении пользователя: {e}")
        return jsonify({"message": "Произошла непредвиденная ошибка"}), 500


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user_api(user_id):
    try:
        user = User.get_or_none(User.id == user_id)
        if user is None:
            return jsonify({'message': 'Пользователь не найден'}), 404

        user.delete_instance()
        return jsonify({'message': 'Пользователь удален'})

    except Exception as e:
        print(f"Ошибка при удалении пользователя: {e}")
        return jsonify({"message": "Произошла непредвиденная ошибка"}), 500


# Новый маршрут для отображения списка пользователей
@app.route('/users', methods=['GET'])
def show_users():
    users = User.select()  # Получите список всех пользователей из базы данных
    return render_template('users.html', users=users)  # Отправьте пользователей в шаблон


if __name__ == '__main__':
    connect_db()
    create_user_table()
    app.run(debug=True)
