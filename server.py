from datetime import datetime, timedelta
import os
import jwt
import logging
from flask import Flask, jsonify, request, render_template , session
import peewee
from peewee import PostgresqlDatabase
import bcrypt
import secrets
from flask_jwt_extended import create_access_token, JWTManager

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

# Замените на надежный ключ!
jwt = JWTManager(app)
db = PostgresqlDatabase(
    DATABASE_NAME,
    user=DATABASE_USER,
    password=DATABASE_PASSWORD,
    host=DATABASE_HOST,
    port=DATABASE_PORT
)


class BaseModel(peewee.Model):
    class Meta:
        database = db

class User(BaseModel):
    username = peewee.CharField(unique=True, max_length=80)
    password_hash = peewee.BlobField()
    password=peewee.CharField()
    fullname1 = peewee.CharField(null=True, default='')
    class Meta:
        db_table = 'users'


class Event(BaseModel):
    username = peewee.CharField(max_length=100, null=False)
    name = peewee.CharField(max_length=100, null=False)
    description = peewee.CharField(max_length=200, null=False)
    start_date = peewee.CharField(max_length=50, null=False)
    start_time = peewee.CharField(max_length=50, null=False)
    end_time = peewee.CharField(max_length=50, null=False)

    class Meta:
        db_table = 'events'


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

def create_event_table():
    if not Event.table_exists():
        db.create_tables([Event])
        print("Таблица 'events' создана успешно!")
    else:
        print("Таблица 'events' уже существует.")


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

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

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
        fullname1 = data.get('fullname1', '')  # Извлекаем fullname1, по умолчанию пустая строка
        if not username or not password:
            return jsonify({"message": "Имя пользователя и пароль обязательны!"}), 400

        hashed_password = hash_password(password)

        with db.atomic():
            try:
                User.create(username=username, password=password, password_hash=hashed_password,
                            fullname1=fullname1)  # Добавляем fullname1
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

        hashed_password_bytes = bytes(user.password_hash)
        if not verify_password(password, hashed_password_bytes):  # Используем bcrypt для проверки
            return jsonify({"message": "Неверное имя пользователя или пароль!"}), 401

        # Установите информацию о пользователе в сессии
        session['user_id'] = user.id

        # Сохраните информацию о сессии в БД


        return jsonify({"message": "Успешный вход!"}), 200

    except Exception as e:
        print(f"Ошибка во время входа: {e}")
        return jsonify({"message": "Произошла непредвиденная ошибка"}), 500



@app.route('/user_data', methods=['GET'])
def userget1():
    return render_template('userget.html')

@app.route('/user_data/<username>', methods=['GET'])
def get_user_data(username):
    try:

        user = User.get(User.username == username)  # Получаем пользователя по имени
        return jsonify({
            'user_id': user.id,
            'username': user.username,
            'password': user.password,
            'fullname1':user.fullname1
        })
    except User.DoesNotExist:
        return jsonify({'message': 'Пользователь не найден'}), 404

@app.route('/update_profile', methods=['GET'])
def update_profile():
    return render_template('updateuser.html')


@app.route('/update_profile/<username>', methods=['PUT'])
def update_user_data(username):
    try:
        # Обновляем данные пользователя в базе данных
        data = request.json

        # Создаем словарь для обновляемых полей
        updates = {}

        if 'username' in data:
            updates['username'] = data['username']
        if 'fullname1' in data:
            updates['fullname1'] = data['fullname1']
        if 'password' in data:
            updates['password'] = data['password']  # Хэшируем пароль перед обновлением
            updates['password_hash'] = hash_password(data['password'])

        # Обновляем пользователя в базе данных
        query = User.update(**updates).where(User.username == username)
        updated_rows = query.execute()  # Выполняем запрос обновления

        if updated_rows == 0:
            return jsonify({'message': 'Пользователь не найден'}), 404

        return jsonify({'message': 'Данные пользователя обновлены успешно'}), 200
    except Exception as e:
        return jsonify({'message': str(e)}), 500  # Обработка других ошибок


@app.route('/add_event', methods=['GET'])
def add_event1():
    return render_template('event.html')

@app.route('/add_event', methods=['POST'])
def add_event():
    data = request.get_json()

    # Проверка наличия необходимых полей
    required_fields = ('name', 'description', 'start_date', 'start_time', 'end_time', 'username')
    if not all(key in data for key in required_fields):
        return jsonify({"message": "Недостаточно данных для создания мероприятия!"}), 400

    # Проверка username (добавлено)
    if not data['username']:
        return jsonify({"message": "Имя пользователя не может быть пустым!"}), 400


    # Преобразование дат и времени с обработкой ошибок
    try:
        start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"message": "Неверный формат даты! Ожидается YYYY-MM-DD."}), 400

    try:
        start_time = datetime.strptime(data['start_time'], '%H:%M').time()
    except ValueError:
        return jsonify({"message": "Неверный формат времени начала! Ожидается HH:MM."}), 400

    try:
        end_time = datetime.strptime(data['end_time'], '%H:%M').time()
    except ValueError:
        return jsonify({"message": "Неверный формат времени окончания! Ожидается HH:MM."}), 400


    # Проверка на перекрытие (улучшенная проверка)
    try:
        overlapping_event = Event.select().where(
            Event.username == data['username'],
            Event.start_date == start_date,
            Event.start_time <= end_time,
            Event.end_time >= start_time
        ).get() # .get() выбросит исключение, если совпадений нет
        return jsonify({"message": "Вы уже запланировали мероприятие на это время!"}), 409
    except Event.DoesNotExist:
        pass # Нет перекрытий


    # Создание нового мероприятия с обработкой исключений
    try:
        with db.atomic(): # Транзакция для атомарности операции
            new_event = Event.create(
                name=data['name'],
                description=data['description'],
                start_date=start_date,
                start_time=start_time,
                end_time=end_time,
                username=data['username']
            )
        return jsonify({"message": "Мероприятие успешно добавлено!", "event_id": new_event.id}), 201
    except IntegrityError as e: # Обработка ошибки целостности БД
        return jsonify({"message": f"Ошибка добавления мероприятия: {e}"}), 500
    except Exception as e:
        return jsonify({"message": f"Непредвиденная ошибка: {e}"}), 500

@app.route('/events1/', methods=['GET'])
def get_events1():
    return render_template('getevents.html')

@app.route('/events1/<username>', methods=['GET'])
def get_events(username):
    try:

        # Получаем все мероприятия для указанного пользователя
        events = Event.select().where(Event.username == username)

        # Преобразуем данные в формат JSON
        event_list = []
        for event in events:
            event_data = {
                'id': event.id,
                'name': event.name,
                'description': event.description,
                'start_date': event.start_date, # Преобразуем дату в ISO формат
                'start_time': event.start_time, # Преобразуем время в ISO формат
                'end_time': event.end_time     # Преобразуем время в ISO формат
            }
            event_list.append(event_data)

        return jsonify(events=event_list), 200

    except Event.DoesNotExist:
        return jsonify({"message": "Мероприятия для данного пользователя не найдены"}), 404
    except Exception as e:
        print(f"Ошибка при получении мероприятий: {e}")
        return jsonify({"message": "Произошла непредвиденная ошибка"}), 500


@app.route('/editevent/', methods=['GET'])
def editevent():
    return render_template('edit_event.html')

@app.route('/editevent/<int:event_id>', methods=['PUT'])
def edit_event(event_id):
    try:
        with db.atomic():
            event = Event.get(Event.id == event_id) # Получаем мероприятие по ID
            data = request.get_json()

            # Обновляем поля мероприятия
            event.username = data.get('username', event.username)
            event.name = data.get('name', event.name)
            event.description = data.get('description', event.description)
            event.start_date = data.get('start_date', event.start_date)
            event.start_time = data.get('start_time', event.start_time)
            event.end_time = data.get('end_time', event.end_time)
            event.save() # Сохраняем изменения

            logging.info(f"Мероприятие с ID {event_id} успешно обновлено")
            return jsonify({"message": "Мероприятие успешно обновлено"}), 200

    except Event.DoesNotExist:
        logging.warning(f"Попытка обновить несуществующее мероприятие (ID: {event_id})")
        return jsonify({"message": "Мероприятие не найдено"}), 404
    except Exception as e:
        logging.exception(f"Непредвиденная ошибка при обновлении мероприятия (ID: {event_id}): {e}")
        return jsonify({"message": "Произошла непредвиденная ошибка"}), 500

@app.route('/logout', methods=['POST'])
def logout():
    try:
        # Убедитесь, что пользователь авторизован
        if 'user_id' not in session:
            return jsonify({"message": "Пользователь не авторизован!"}), 401

        # Удалите информацию о пользователе из сессии
        session.pop('user_id', None)

        # Здесь можно добавить код для обновления информации о сессии в БД, если это необходимо

        return jsonify({"message": "Вы успешно вышли!"}), 200

    except Exception as e:
        print(f"Ошибка во время выхода: {e}")
        return jsonify({"message": "Произошла непредвиденная ошибка"}), 500


# Новый маршрут для отображения списка пользователей
@app.route('/users', methods=['GET'])
def show_users():
    users = User.select()  # Получите список всех пользователей из базы данных
    return render_template('users.html', users=users)  # Отправьте пользователей в шаблон


if __name__ == '__main__':

    connect_db()
    create_user_table()
    create_event_table()
    app.run(debug=True)
