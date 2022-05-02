from distutils.log import debug
from flask import Flask, redirect, url_for, render_template, request, session, flash
from pytrends.request import TrendReq
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from flask_bcrypt import Bcrypt
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, IntegerField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_mail import Mail, Message
from flask_socketio import SocketIO

import json
import ee
import folium
import geemap.foliumap as geemap
import plotly
import pandas as pd
import plotly.graph_objects as go

app = Flask(__name__)
#Base de datos
database = SQLAlchemy(app)

#Encriptado
bcrypt = Bcrypt(app)

mail = Mail(app)

socketio = SocketIO(app, cors_allowed_origins='*')

app.config['SQLALCHEMY_DATABASE_URI'] = '//prodiplosis2022:adminprodiplosis@34.122.156.243:$PORT/$DATABASE'

## Schemas

class User(database.Model, UserMixin):
	id = database.Column(database.Integer, primary_key=True)
	email = database.Column(database.String(30), unique=True)
	username = database.Column(database.String(20), nullable=False, unique=True)
	password = database.Column(database.String(80), nullable=False)
	profile_pic = database.Column(database.String(40), nullable=False, default='default.jpg')
	bio_content = database.Column(database.String(1000))
	verified = database.Column(database.Boolean(), default=False)
	commenter = database.relationship('Comment', backref='commenter', lazy='dynamic')
	wish = database.relationship('Wish', backref='liker', lazy='dynamic')

class RegisterForm(FlaskForm):
	email = StringField(validators=[InputRequired(), Email(message="Email invalido"), 
	Length(min=1, max=50)], render_kw={"placeholder": "Email"})
	username = StringField(validators=[InputRequired(), Length(min = 4, max = 20)], 
	render_kw = {"placeholder":"Usuario"})
	password = PasswordField(validators=[InputRequired(), Length(min = 4, max = 20)], 
	render_kw = {"placeholder":"Contraseña"})
	password_c = PasswordField(validators=[InputRequired(), Length(min = 4, max = 20)],
	render_kw = {"placeholder":"Confirmar contraseña"})
	submit = SubmitField("Registrar")

	def validate_username(self, username):
		existing_user_username = User.query.filter_by(username=username.data).first()
		if existing_user_username:
			raise ValidationError("El usuario ya existe. Por favor escoge un nombre de usuario diferente")

	def validate_email(self, email):
		existing_user_email = User.query.filter_by(email=email.data).first()
		if existing_user_email:
			raise ValidationError("El email ya pertenece a otro usuario. Por favor introduce uno diferente.")


class LoginForm(FlaskForm):
	username = StringField("Username", validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Usuario"})
	password = PasswordField("Password", validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Contraseña"})
	submit = SubmitField("Iniciar Sesión")

	def validate_username(self, username):
		username = User.query.filter_by(username=username.data).first()
		if not username:
			raise ValidationError('El usuario no existe.')

class ForgotPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Email invalido"), Length(max=50)], render_kw={"placeholder": "Email"})
    submit = SubmitField("Enviar correo de nueva contraseña")


class ResetPasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message = "Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Nueva contraseña"})


class ChangePasswordForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    current_password = PasswordField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Contraseña actual"})
    new_password = PasswordField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Nueva contraseña"})
    submit = SubmitField("Change Password")


class DeleteAccountForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Email"})
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Nombre usuario"})
    password = PasswordField(validators=[InputRequired(), Length(min=4)], render_kw={"placeholder": "Contraseña"})
    submit = SubmitField("Eliminar mi cuenta")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/trends', methods=['GET', 'POST'])
def trends():
    if request.method == 'POST' and 'got' in request.form:
        search = request.form["got"]
        kw_list = [search]
        pytrends_ES = TrendReq(hl='es-ES', tz = -300) 
        pytrends_ES.build_payload(kw_list, timeframe='2004-01-01 2022-12-31', geo = 'CO')
        data = pytrends_ES.interest_over_time() 
        name = data.columns
        data = data.reset_index()
        if len(data) != 0:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x = data['date'], y = data[name[0]], name = name[0]))
        else:
            fig = go.Figure()
            fig.add_trace(go.Scatter(name = 'No data'))

    else:
        pytrends_ES = TrendReq(hl='es-ES', tz = -300) 
        kw_list = ["caracha", "prodiplosis", "caracha + prodiplosis"]
        pytrends_ES.build_payload(kw_list, timeframe='2004-01-01 2022-12-31', geo = 'CO')
        data = pytrends_ES.interest_over_time() 
        data = data.reset_index()
        if len(data) != 0:
            fig = go.Figure()
            fig.add_trace(go.Scatter(x = data['date'], y = data['prodiplosis'], name = data['prodiplosis'].name))
            fig.add_trace(go.Scatter(x = data['date'], y = data['caracha'], name = data['caracha'].name))
            fig.add_trace(go.Scatter(x = data['date'], y = data['caracha + prodiplosis'],name = data['caracha + prodiplosis'].name))
        else:
            fig = go.Figure()
            fig.add_trace(go.Scatter(name = 'No data'))    
    
    fig.update_layout(
    title="Google Trends",
    xaxis_title="Tiempo (años)",
    yaxis_title="Indice Relativo de Busqueda",
    legend_title="Busquedas",
    showlegend = True,
    height = 600,
    font=dict(
        family="Courier New, monospace",
        size=16
    ))

    by_region = pytrends_ES.interest_by_region(resolution='STATES', inc_low_vol=True, inc_geo_code=False)

    df = by_region
    
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return render_template('trends.html', 
                            graphJSON = graphJSON, 
                            tables=[df.to_html(classes='data', header="true")])

@app.route('/maps')
def maps():
    ee.Initialize()
    figure = folium.Figure()
    Map = geemap.Map(plugin_Draw = True, 
                         Draw_export = False,
                         plugin_LayerControl = False,
                         location = [4.3, -76.1],
                         zoom_start = 10,
                         plugin_LatLngPopup = False)
                         
    Map.add_basemap('HYBRID')
    Map.add_to(figure)
    figure.save('templates/map.html')
    return render_template('maps.html')

@app.route('/maps/map')
def map():
    return render_template('map.html')

@app.route("/registrar-usuario", methods=['POST','GET'])
def registrar():
	registerform = RegisterForm()
	if registerform.validate_on_submit():
		if registerform.password.data == registerform.password_c.data:
			hashed_password = bcrypt.generate_password_hash(registerform.password.data)
			new_user = User(username=registerform.username.data, 
			password=hashed_password,
			email = registerform.email.data)
			database.session.add(new_user)
			database.session.commit()
			flash("Tu cuenta ha sido creada exitosamente!")
			return redirect(url_for('login'))
		else:
			return redirect(url_for('registrar'))

	return render_template("signup.html", registerform = registerform)

@app.route("/inicio-de-sesion", methods = ['POST','GET'])
def login():
	loginform = LoginForm()
	if loginform.validate_on_submit():
		user = User.query.filter_by(username = loginform.username.data).first()
		if user:
			if bcrypt.check_password_hash(user.password, loginform.password.data):
				login_user(user)
				return redirect(url_for('home'))
			if not bcrypt.check_password_hash(user.password, loginform.password.data):
				flash("Contraseña incorrecta.")
		if not user:
			flash("El usuario no existe.")
	if current_user.is_authenticated:
		return redirect('home')
	else:
		return render_template("login.html", loginform = loginform)

@app.route("/cerrar-sesion", methods=['POST','GET'])
@login_required
def cerrar_sesion():
	session.clear()
	logout_user()
	return redirect(url_for('home'))

@app.route("/cambiar-contra", methods=['GET', 'POST'])
@login_required
def cambiar_contrasena():
	change_form = ChangePasswordForm()
	if change_form.validate_on_submit():
		user = User.query.filter_by(email = change_form.email.data).first()
		hashed_password = bcrypt.generate_password_hash(change_form.new_password.data).decode('utf-8')
		if change_form.email.data != current_user.email:
			flash("Email invalido")
			return redirect(url_for('cambiar_contrasena'))
		if not bcrypt.check_password_hash(current_user.password, change_form.current_password.data):
			flash("Contraseña invalida")
			return redirect(url_for('cambiar_contrasena'))
		else:
			current_user.password = hashed_password
			database.session.commit()
			flash('Tu contraeña ha sido actualizada!')
			return redirect(url_for('perfil-usuario'))
	return render_template("cambiarcontra.html", form = change_form, title="Cambiar contraseña")

@app.route("/borrar-cuenta", methods=['GET', 'POST'])
@login_required
def borrar_cuenta():
	delete_form = DeleteAccountForm()
	#comments = Comment.query.filter_by(commenter=current_user).all()
	user = User.query.filter_by(email = delete_form.email.data).first()
	if delete_form.validate_on_submit():
		if delete_form.email.data != current_user.email or delete_form.username.data != current_user.username:
			flash('El email o nombre de usuario no esta asociado con tu cuenta.')
			return redirect(url_for('borrar_cuenta'))
		
		database.session.delete(user)
		database.session.commit()
		flash('Tu cuenta ha sido eliminada', 'Éxito!')
		return redirect(url_for('home'))
	return render_template("borrarcuenta.html", form = delete_form, title = "Borrar mi cuenta")

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('¿Olvidaste tu contraseña?',
                  sender='ksquiroga@uninorte.edu.co',
                  recipients=[user.email])
    msg.body = f'''Para reestablecer tu contraseña, da click en el siguiente link: 
	{url_for('resetear-contra', token=token, _external=True)} 
	Si no solicitaste el reestablecimiento de la contraseña, ignora este mensaje. '''
    mail.send(msg)

@app.route("/olvide-contra", methods = ["GET", "POST"])
def olvide_contra():
	forgot_form = ForgotPasswordForm()
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	if forgot_form.validate_on_submit():
		user = User.query.filter_by(email = forgot_form.email.data).first()
		send_reset_email(user)
		flash("Un email fue enviado a tu correo para reestablecer la contraseña.", 'Éxito!')
	return render_template("olvidecontra.html", form = forgot_form, title="Olvidé contraseña")

@app.route("/resetear-contra/<token>", methods=["GET", "POST"])
def resetear_contra(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('Este es un token invalido', 'warning')
        return redirect(url_for('olvide-contra'))
    reset_form = ResetPasswordForm()
    if reset_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(reset_form.password.data)
        user.password = hashed_password
        database.session.commit()
        flash('Tu contraseña ha sido actualizada!', 'success')
        return redirect(url_for('home'))
    return render_template('resetearcontra.html', title = 'Reset Password', form = reset_form)

if __name__ == '__main__':
    app.run(debug = True, port = 5001)