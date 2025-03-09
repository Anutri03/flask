from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('login.html')


@app.route('/landingpagemain')
def landingpagemain():
    return render_template('landingpagemain.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/technology')
def technology(): 
    return render_template('technology.html')

@app.route('/research')
def research(): 
    return render_template('research.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))




if __name__ == '__main__':
    app.run(debug=True)


