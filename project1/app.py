from flask import Flask, flash, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from textblob import TextBlob
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from werkzeug.security import generate_password_hash, check_password_hash
import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import InputRequired, Length, EqualTo

app = Flask(__name__)
db_type = os.getenv('DB_TYPE', 'sqlite')
if db_type == 'mysql':

    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:sqlpassword@1234@localhost/db_name'
else:

    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///feedback.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'supersecretkey'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, nullable=False)
    feedback = db.Column(db.String(500), nullable=False)
    sentiment = db.Column(db.String(50), nullable=False)
    source = db.Column(db.String(100), nullable=False)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)


with app.app_context():
    db.create_all()

    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', password=generate_password_hash('admin123'), role='Admin')
        db.session.add(admin_user)

    if not User.query.filter_by(username='user').first():
        regular_user = User(username='user', password=generate_password_hash('user123'), role='Regular')
        db.session.add(regular_user)

    db.session.commit()


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('Admin', 'Admin'), ('Regular', 'Regular')], validators=[InputRequired()])


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def upload_file():
    if 'file' not in request.files:
        return None, "No file uploaded"
    file = request.files['file']
    file_path = os.path.join('uploads', file.filename)
    file.save(file_path)
    return file_path, None


def load_data():
    data_frames = []
    data_frames.append(pd.read_csv(r'data sources/feedback.csv'))
    data_frames.append(pd.read_json(r'data sources/feedback.json'))
    data_frames.append(pd.read_excel(r'data sources/feedback.xlsx'))
    data_frames.append(pd.read_xml(r'data sources/feedback.xml'))
    df = pd.concat(data_frames, ignore_index=True).drop_duplicates()
    return df


def validate_and_transform(df):
    # Validation
    df = df[df['customer_id'].notna() & (df['customer_id'] > 0)]

    df['feedback'] = df['feedback'].astype(str)
    df = df[df['feedback'].apply(lambda x: len(x) > 5)]

    if 'sentiment' in df.columns:
        df = df[df['sentiment'].isin(['Positive', 'Negative'])]
    else:
        pass

    df = df.drop_duplicates(subset=['feedback'])

    df = df[df['source'].notna()]

    df['feedback'] = df['feedback'].apply(lambda x: re.sub(r'\W+', ' ', x.lower()))

    df['source'] = df['source'].apply(lambda x: x.lower() if isinstance(x, str) else x)

    df['feedback_length'] = df['feedback'].apply(len)
    df['sentiment'] = df['feedback'].apply(lambda x: 'Positive' if TextBlob(x).sentiment.polarity > 0 else 'Negative')

    df = df[df['feedback_length'] >= 10]

    df['sentiment_score'] = df['feedback'].apply(lambda x: TextBlob(x).sentiment.polarity)

    return df


def save_to_db(df):
    for _, row in df.iterrows():
        feedback = Feedback(customer_id=row['customer_id'], feedback=row['feedback'],
                            sentiment=row['sentiment'], source=row['source'])
        db.session.add(feedback)
    db.session.commit()


def create_charts(df):
    charts = []

    if not os.path.exists('static'):
        os.makedirs('static')

    plt.figure(figsize=(8, 6))
    sns.countplot(x='sentiment', data=df)
    plt.title('Sentiment Distribution')
    plt.savefig('static/sentiment_distribution.png')
    charts.append('static/sentiment_distribution.png')
    plt.close()

    plt.figure(figsize=(8, 6))
    sns.countplot(x='sentiment', hue='source', data=df)
    plt.title('Sentiment by Source')
    plt.savefig('static/sentiment_by_source.png')
    charts.append('static/sentiment_by_source.png')
    plt.close()

    plt.figure(figsize=(8, 6))
    sns.barplot(x='customer_id', y='sentiment', data=df)
    plt.title('Customer Sentiment')
    plt.savefig('static/customer_sentiment.png')
    charts.append('static/customer_sentiment.png')
    plt.close()

    df['feedback_length'] = df['feedback'].apply(len)
    plt.figure(figsize=(8, 6))
    sns.boxplot(x='sentiment', y='feedback_length', data=df)
    plt.title('Feedback Length by Sentiment')
    plt.savefig('static/feedback_length_by_sentiment.png')
    charts.append('static/feedback_length_by_sentiment.png')
    plt.close()

    plt.figure(figsize=(8, 6))
    sns.countplot(x='customer_id', data=df)
    plt.title('Customer ID Distribution')
    plt.savefig('static/customer_id_distribution.png')
    charts.append('static/customer_id_distribution.png')
    plt.close()

    plt.figure(figsize=(8, 6))
    sns.histplot(df['feedback_length'], bins=20, kde=True)
    plt.title('Feedback Length Distribution')
    plt.xlabel('Feedback Length')
    plt.ylabel('Frequency')
    plt.savefig('static/feedback_length_distribution.png')
    charts.append('static/feedback_length_distribution.png')
    plt.close()

    return charts


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash("Invalid username or password", "error")
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        role = form.role.data
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists.", "error")
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role != 'Admin':
        return redirect(url_for('dashboard'))

    charts = []
    if request.method == 'POST':
        file_path, error_message = upload_file()
        if error_message is None:
            df = load_data()
            df = validate_and_transform(df)
            save_to_db(df)
            charts = create_charts(df)

    df = load_data()
    df = validate_and_transform(df)
    charts = create_charts(df)

    return render_template('admin_dashboard.html', charts=charts, role=current_user.role)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.role != 'Regular':
        return redirect(url_for('admin_dashboard'))

    charts = []
    if request.method == 'POST':
        file_path, error_message = upload_file()
        if error_message is None:
            df = load_data()
            df = validate_and_transform(df)
            save_to_db(df)
            charts = create_charts(df)

    df = load_data()
    df = validate_and_transform(df)
    charts = create_charts(df)

    return render_template('dashboard.html', charts=charts, role=current_user.role)


if __name__ == '__main__':
    app.run(debug=True)
