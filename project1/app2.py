import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, EqualTo, ValidationError
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

app = Flask(__name__)
app.secret_key = 'supersecretkey'

db_type = os.getenv('DB_TYPE', 'sqlite')

if db_type == 'mysql':
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:sqlpassword@1234@localhost/db_name'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Performance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Float, nullable=False)
    term = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=150)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('Student', 'Student'), ('Teacher', 'Teacher'), ('Admin', 'Admin')], validators=[InputRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("Username already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=150)])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

def load_and_process_data():
    data_frames = [
        pd.read_csv(r'data sources/grades.csv'),
        pd.read_json(r'data sources/grades.json'),
        pd.read_excel(r'data sources/grades.xlsx'),
        pd.read_xml(r'data sources/grades.xml'),
        pd.DataFrame(pd.read_html(r'data sources/grades.html')[0])
    ]
    df = pd.concat(data_frames, ignore_index=True).drop_duplicates()
    #Validations

    df = df[df['student_id'].notna() & df['score'].notna() & df['subject'].notna()]
    df = df[df['score'].between(0, 100)]
    df = df[df['student_id'] > 0]

    valid_terms = ['Fall 2023', 'Spring 2024', 'Fall 2024', 'Spring 2025']
    df = df[df['term'].isin(valid_terms)]

    df = df[df['subject'].str.len() > 2]
    #transformations

    df['subject'] = df['subject'].str.title()
    df['term'] = df['term'].str.title()
    df['score'] = df['score'].clip(0, 100)

    df['performance_level'] = df['score'].apply(
        lambda x: 'Excellent' if x >= 85 else 'Good' if x >= 70 else 'Needs Improvement' if x >= 50 else 'Fail'
    )

    if 'name' in df.columns:
        df['full_name'] = df['name'].apply(lambda x: ' '.join(x.split()[:2]))

    for _, row in df.iterrows():
        record = Performance(student_id=row['student_id'], subject=row['subject'], score=row['score'], term=row['term'])
        db.session.add(record)
    db.session.commit()

def create_charts(df, role):
    charts = []
    if not os.path.exists('static'):
        os.makedirs('static')

    if role == 'Student':
        plt.figure()
        sns.histplot(df['score'], kde=True)
        plt.title('Score Distribution')
        plt.savefig('static/score_distribution.png')
        charts.append('score_distribution.png')

    elif role == 'Teacher':
        plt.figure()
        sns.boxplot(x='subject', y='score', data=df)
        plt.title('Scores by Subject')
        plt.savefig('static/scores_by_subject.png')
        charts.append('scores_by_subject.png')

        plt.figure()
        sns.lineplot(x='term', y='score', hue='subject', data=df)
        plt.title('Scores Over Terms')
        plt.savefig('static/scores_over_terms.png')
        charts.append('scores_over_terms.png')

    elif role == 'Admin':
        plt.figure()
        sns.countplot(x='subject', data=df)
        plt.title('Number of Records per Subject')
        plt.savefig('static/records_per_subject.png')
        charts.append('records_per_subject.png')

        plt.figure()
        sns.lineplot(x='term', y='score', data=df, estimator='mean')
        plt.title('Average Scores Over Time')
        plt.savefig('static/average_scores_over_time.png')
        charts.append('average_scores_over_time.png')

    return charts

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user:
            if user.password == form.password.data:
                login_user(user)
                flash("Logged in successfully.", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect password. Please try again.", "danger")
        else:
            flash("Username not found. Please try again.", "danger")

    return render_template('login2.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(username=form.username.data,
                    password=form.password.data,
                    role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful!", "success")
        return redirect(url_for('login'))

    return render_template('register2.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    df = pd.read_sql(Performance.query.statement, db.engine)
    pdf_html = df.to_html()

    charts = create_charts(df, current_user.role)
    return render_template('dashboard2.html', charts=charts, role=current_user.role, pdf_html=pdf_html)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
