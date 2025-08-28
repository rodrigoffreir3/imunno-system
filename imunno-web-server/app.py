import os
from flask import Flask, request, redirect, url_for, render_template_string
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = '/app/uploads'
ALLOWED_EXTENSIONS = {'txt', 'php', 'js'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def upload_form():
    return render_template_string('''
    <!doctype html>
    <title>Imunno Test Server</title>
    <h1>Upload a file to test Imunno Agent</h1>
    <p><em>Allowed extensions: txt, php, js</em></p>
    <form method=post enctype=multipart/form-data action="/upload">
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    ''')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Ensure the upload folder exists
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return f'File {filename} uploaded successfully!'
    return 'File type not allowed'

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)

