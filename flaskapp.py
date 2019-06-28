'''
Zami Talukder

'''

from flask import Flask, url_for, redirect, request, session
import jinja2
import os
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form,validators,StringField,PasswordField
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
import filetype
from PIL import Image
from datetime import datetime

app = Flask(__name__, static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/app_sec_homework'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'MySecretKey'
app.config['MAX_CONTENT_LENGTH'] = 1024*1025*5
app.config['UPLOAD_FOLDER'] = 'static'

#HTML templates are stored in templates folder
jinjaDirectory = os.path.join(os.path.dirname(__file__),'templates')
myJinja = jinja2.Environment(loader=jinja2.FileSystemLoader(jinjaDirectory),autoescape=True)

userDatabase = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'tologin'


#Member class represents member table in SQL database
class Member(UserMixin, userDatabase.Model):
    __tablename__ = 'member'
    id = userDatabase.Column('id', userDatabase.Integer,autoincrement=True ,primary_key=True)
    username = userDatabase.Column('username',userDatabase.String(20))
    password = userDatabase.Column('password',userDatabase.String(255))
    first_name = userDatabase.Column('first_name',userDatabase.String(20))
    last_name = userDatabase.Column('last_name',userDatabase.String(20))

class Images(UserMixin, userDatabase.Model):
    __tablename__ = 'images'
    id = userDatabase.Column('image_id', userDatabase.Integer, autoincrement=True, primary_key=True)
    user_id = userDatabase.Column('user_id', userDatabase.Integer)
    image = userDatabase.Column('image', userDatabase.String(255))

class User_Action(UserMixin, userDatabase.Model):
    __tablename__ = 'user_actions'
    action = userDatabase.Column('action',userDatabase.String(255), primary_key=True)
    user_id = userDatabase.Column('user_id', userDatabase.Integer)
    time = userDatabase.Column('time', userDatabase.Time)

@login_manager.user_loader
def load_user(user_id):
    return Member.query.get(user_id)

#RegisterForm used to verify forms when registering
class RegisterForm(Form):
    username = StringField('username',[validators.Length(min=1,max=20)])
    password = PasswordField('password',[validators.DataRequired(),validators.Length(min=1,max=20)])
    first_name = StringField('first_name', [validators.Length(min=1, max=20)])
    last_name = StringField('last_name', [validators.Length(min=1,max=20)])


def log_action(new_action, the_id=0):
    new_entry = User_Action(action=new_action, user_id=the_id, time=datetime.now())
    userDatabase.session.add(new_entry)
    userDatabase.session.commit()

#toregister handles registration of a new user
@app.route('/toregister',methods=["GET","POST"])
def toregister():
    template = myJinja.get_template('toregister.html')
    try:
        if request.method == "POST":
            registrationForm = RegisterForm(request.form)
            if registrationForm.validate():
                #Hashes password and checks if username already exists, registers user with given info if tests pass
                hashedPassword = generate_password_hash(request.form['password']+request.form['username'],method='sha256')
                newMember = Member(username=request.form['username'],password=hashedPassword,
                                   first_name=request.form['first_name'], last_name=request.form['last_name'])
                nameInUse = Member.query.filter_by(username=request.form['username']).first()

                log_action('attempted_registration ' + request.form['username'])

                if nameInUse:
                    return template.render(errorInfo="Username already in use. Please try again")
                else:
                    userDatabase.session.add(newMember)
                    userDatabase.session.commit()
                    session['id'] = newMember.id
                    log_action('successful_registration', session['id'])

                    addedUser = Member.query.filter_by(username=request.form['username']).first()
                    login_user(addedUser)

                    return redirect(url_for('homepage'))

            else:
                log_action('invalid_registration_form')
                return template.render(errorInfo= "Invalid information. Please try again")

        else:
            pass
    except Exception as e:
        print e
    return template.render()


# tologin handles users logging in
@app.route('/tologin', methods=["GET", "POST"])
def tologin():
    template = myJinja.get_template('tologin.html')
    try:
        if request.method == "POST":
            inputUsername = request.form['username']
            foundUser = Member.query.filter_by(username=inputUsername).first()
            if foundUser:
                if check_password_hash(foundUser.password, request.form['password'] + request.form['username']): #Uses hashed passwords when checking passwords
                    
                    session['id'] = foundUser.id
                    log_action('logged in', session['id'])
                    login_user(foundUser)
                    return redirect(url_for('homepage'))
                else:
                    log_action('attempted_log_in ' + request.form['username'])
                    return template.render(errorInfo="Username and password do not match")
            else:
                log_action('unknown_username ' + request.form['username'])
                return template.render(errorInfo="No such username found")
    except Exception as e:
        print e.message
    return template.render()


#tologout handles users logging out and redirects to tologin
@app.route('/tologout')
@login_required
def tologout():
    log_action('logged_out', session['id'])
    logout_user()
    return redirect(url_for('tologin'))


#homepage is where users can search keywords
#Redirected to login if user is not logged in
@app.route('/homepage',methods=["GET","POST"])
@login_required
def homepage():
    template = myJinja.get_template('homepage.html')
    images = Images.query.filter_by(user_id=session['id']).all()
    imageList = []
    for i in images:
        imageList.append(i.image)
    log_action('visited_homepage', session['id'])
    return template.render(imagePath=imageList)

@app.route('/upload', methods=["POST"])
@login_required
def upload():
    try:
        if 'image' not in request.files:
            log_action('no_images', session['id'])
            return redirect(url_for('homepage'))
        file = request.files['image']
        #checks image type
        if file.filename.rsplit('.', 1)[1].lower() != 'png':
            log_action('failed_uploaded_image', session['id'])
            return redirect(url_for('homepage'))

        filename = generate_password_hash(file.filename+str(session['id']),method='sha256') + '.png'
        #saves it into folder to resize
        filename = secure_filename(filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        #ensure file type is png
        ext = filetype.guess('static/%s' % filename)
        if ext is None or ext.extension != 'png':
            os.remove('static/%s' % filename)
            log_action('image_disguised_as_png', session['id'])
            return redirect(url_for('homepage'))
        
        log_action('uploaded_image', session['id'])
        #resizes image
        im = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        dimension = min(im.size)
        im = im.resize((dimension, dimension), Image.ANTIALIAS)
        os.remove('static/%s' % filename) #removes the old file
        filename = '0' + filename
        im.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        output_file = url_for('static', filename=filename)

        newImage = Images(user_id=session['id'], image=output_file)
        userDatabase.session.add(newImage)
        userDatabase.session.commit()

        #outputs image
        template = myJinja.get_template('homepage.html')
        return template.render(imagePath=[output_file])

    except Exception as e:
        print e
    return redirect(url_for('homepage'))


@app.after_request
def apply_caching(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


if __name__ == "__main__":
    app.run()
