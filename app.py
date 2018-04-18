from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from wtforms.widgets import TextArea
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)

# config mysql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Austin78759'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
#  init mySQL

mysql = MySQL(app)


# home
@app.route('/')
def index():
    return render_template('home.html')

# about
@app.route('/about')
def about():
    return render_template('about.html') 

# all articles
@app.route('/articles')
def articles():
    # create cursor
    cur = mysql.connection.cursor()

    # get articles
    result = cur.execute('select * from articles')

    articles= cur.fetchall()
    if result > 0:
        return render_template('articles.html', articles=articles)
    else:
        msg = 'No Articles found'
        return render_template('articles.html', msg=msg)

    # close connection
    cur.close()

# add article form
class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=500)])
    body = TextAreaField('body', [validators.Length(min=30)])
    doc_link = StringField('doc_link', [validators.Length(min=4)])



# individual article
@app.route('/article/<string:id>/')
def article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get article
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()

    return render_template('article.html', article=article)

class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Username Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

# user register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # commit to db
        mysql.connection.commit()

        # close connection
        cur.close()

        # flash message
        flash('you are now registered and can log in', 'success')
        return redirect(url_for('login'))

    
    return render_template('register.html', form=form)

# user login

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # get form fields
        username = request.form['username']
        password_candidate = request.form['password']

        # create handler 
        cur = mysql.connection.cursor()

        result = cur.execute("SELECT * FROM users WHERE username = %s", [username]) 

        if result > 0:
            # get stored hash
            data = cur.fetchone()
            password = data['password']

            # compare passwords
            if sha256_crypt.verify(password_candidate, password):
                # passed
                session['logged_in'] = True
                session['username'] = username

                flash('you are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'password not matched'
                return render_template('login.html', error=error)
            cur.close()    
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)
           

    return render_template('login.html') 
# check if user logged in with decorator
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, please login', 'danger')
            return redirect(url_for('index'))
    return wrap


# logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('you are now logged out', 'success')
    return redirect(url_for('index'))

# dashboard after login
@app.route('/dashboard')
@is_logged_in
def dashboard():
    # create cursor
    cur = mysql.connection.cursor()

    # get articles
    result = cur.execute('select * from articles')

    articles= cur.fetchall()
    if result > 0:
        return render_template('dashboard.html', articles=articles)
    else:
        msg = 'No Articles found'
        return render_template('dashboard.html', msg=msg)

    # close connection
    cur.close()


# add articles route
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data
        doc_link = form.doc_link.data

        # create cursor
        cur = mysql.connection.cursor()
        # execute
        cur.execute("INSERT INTO articles(title, body, doc_link) Values(%s, %s, %s)", (title, body, doc_link))

        # commit to db
        mysql.connection.commit()

        #close connection
        cur.close()

        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)

    # edit articles route
@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    # create cursor
    cur=mysql.connection.cursor()

    # get article by id
    result = cur.execute('SELECT * FROM articles WHERE id = %s', [id])

    article = cur.fetchone()

    # get form
    form = ArticleForm(request.form)
    
    form.title.data = article['title']
    form.body.data = article['body']
    form.doc_link.data = article['doc_link']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']
        doc_link = form['doc_link']

  
        # execute
        cur.execute("UPDATE articles SET title=%s, body=%s, doc_link=%s WHERE id= %s", (title, body, doc_link, id))

        # commit to db
        mysql.connection.commit()

        #close connection
        cur.close()

        flash('Article UPDATED', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form=form)


# delete article
@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM articles WHERE id = %s", [id])

    # Commit to DB
    mysql.connection.commit()

    #Close connection
    cur.close()

    flash('Article Deleted', 'success')

    return redirect(url_for('dashboard'))


# spin up page
if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)


