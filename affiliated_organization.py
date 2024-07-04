import datetime
import os
import uuid
import re
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import generate_csrf
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///events.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['UPLOAD_FOLDER'] = 'uploads/'
db = SQLAlchemy(app)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)  # Add the title column
    language = db.Column(db.String(50), nullable=False)  # New field for language
    category = db.Column(db.String(50), nullable=False)  # New field for category
    start_date = db.Column(db.String(10), nullable=False)
    end_date = db.Column(db.String(10), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)  # Renamed from district to city
    venue = db.Column(db.String(200), nullable=True)  # New field for venue
    description = db.Column(db.String(1000), nullable=False)  # Increased limit
    image_url = db.Column(db.String(200), nullable=True)
    archive_date = db.Column(db.String(10), nullable=True)  # New field for archive date

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg'}

def validate_string_no_special_chars(input_string):
    return bool(re.match("^[A-Za-z0-9 _]*$", input_string))

def validate_event_data(name, start_date, end_date, state, district, description, event_image):
    if not name or len(name) > 100 or not validate_string_no_special_chars(name):
        flash('Event name is required, must be under 100 characters, and cannot contain special characters.')
        return False
    
    try:
        event_start_date = datetime.datetime.strptime(start_date, "%Y-%m-%d")
        event_end_date = datetime.datetime.strptime(end_date, "%Y-%m-%d")
        if event_start_date < datetime.datetime.now():
            flash('Event start date cannot be in the past.')
            return False
        if event_end_date < event_start_date:
            flash('Event end date cannot be before the event start date.')
            return False
    except ValueError:
        flash('Invalid date format. Expected YYYY-MM-DD.')
        return False
    
    if not state or len(state) > 100 or not validate_string_no_special_chars(state):
        flash('Event state is required, must be under 100 characters, and cannot contain special characters.')
        return False

    if not district or len(district) > 100 or not validate_string_no_special_chars(district):
        flash('Event district is required, must be under 100 characters, and cannot contain special characters.')
        return False
    
    if not description or len(description) > 500:
        flash('Event description is required and must be under 500 characters.')
        return False
    
    if event_image:
        if not allowed_file(event_image.filename):
            flash('Invalid image format. Allowed formats are PNG, JPG, JPEG.')
            return False
        if event_image.content_length > 5 * 1024 * 1024:  # 5 MB
            flash('Image file size must be under 5 MB.')
            return False

    return True

def save_uploaded_file(event_image):
    if event_image:
        ext = secure_filename(event_image.filename).rsplit('.', 1)[1].lower()
        filename = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4()}.{ext}")
        event_image.save(filename)
        return filename
    return None

@app.route('/', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'POST':
        name = request.form['event_name']
        start_date = request.form['event_start_date']
        end_date = request.form['event_end_date']
        state = request.form['event_state']
        city = request.form['event_district']
        description = request.form['event_description']
        event_image = request.files.get('event_image')

        if not validate_event_data(name, start_date, end_date, state, city, description, event_image):
            return redirect(request.url)

        existing_event = Event.query.filter_by(title=name, start_date=start_date, end_date=end_date, state=state, city=city).first()
        if existing_event:
            flash('An event with the same name, dates, state, and city already exists.')
            return redirect(request.url)

        filename = save_uploaded_file(event_image)

        new_event = Event(title=name, language='English', category='Music', start_date=start_date, end_date=end_date, state=state, city=city, description=description, image_url=filename, venue=None, archive_date=None)
        db.session.add(new_event)
        db.session.commit()
        flash('Event Added Successfully!')

    all_events = Event.query.all()
    csrf_token = generate_csrf()
    return render_template('dashboard.html', events=all_events, csrf_token=csrf_token)



@app.route('/', methods=['GET', 'POST'])
def original_dashboard():
    if request.method == 'POST':
        name = request.form['event_name']
        start_date = request.form['event_start_date']
        end_date = request.form['event_end_date']
        state = request.form['event_state']
        district = request.form['event_district']
        description = request.form['event_description']
        event_image = request.files.get('event_image')

        if not validate_event_data(name, start_date, end_date, state, district, description, event_image):
            return redirect(request.url)

        existing_event = Event.query.filter_by(title=name, start_date=start_date, end_date=end_date, state=state, city=district).first()
        if existing_event:
            flash('An event with the same name, dates, state, and district already exists.')
            return redirect(request.url)

        filename = save_uploaded_file(event_image)

        new_event = Event(title=name, start_date=start_date, end_date=end_date, state=state, city=district, description=description, image_url=filename)
        db.session.add(new_event)
        db.session.commit()
        flash('Event Added Successfully!')

    all_events = Event.query.all()
    csrf_token = generate_csrf()
    return render_template('dashboard.html', events=all_events, csrf_token=csrf_token)

@app.route('/edit_event/<int:event_id>', methods=['GET', 'POST'])
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    if request.method == 'POST':
        name = request.form['event_name']
        start_date = request.form['event_start_date']
        end_date = request.form['event_end_date']
        state = request.form['event_state']
        district = request.form['event_district']
        description = request.form['event_description']

        if not validate_event_data(name, start_date, end_date, state, district, description, None):
            flash('Event data is not valid')
            return redirect(request.url)

        event.title = name
        event.start_date = start_date
        event.end_date = end_date
        event.state = state
        event.city = district
        event.description = description

        event_image = request.files.get('event_image')
        if event_image and allowed_file(event_image.filename):
            filename = save_uploaded_file(event_image)
            if filename:
                event.image_url = filename
        elif event_image:
            flash('Invalid image format')
            return redirect(request.url)

        db.session.commit()
        flash('Event updated successfully!')
        return redirect(url_for('dashboard'))

    return render_template('edit_event.html', event=event)

@app.route('/view_event/<int:event_id>')
def view_event(event_id):
    event = Event.query.get_or_404(event_id)
    return render_template('view_event.html', event=event)

@app.route('/delete_event/<int:event_id>')
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    try:
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted successfully!')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the event.')
    return redirect(url_for('dashboard'))

@app.route('/delete_all_events')
def delete_all_events():
    try:
        num_deleted = Event.query.delete()
        db.session.commit()
        flash(f'All events deleted successfully! Total: {num_deleted}')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting all events.')
    return redirect(url_for('dashboard'))

@app.route('/api/events', methods=['GET'])
def get_events():
    all_events = Event.query.all()
    events_list = [
        {'id': e.id, 'name': e.title, 'start_date': e.start_date, 'end_date': e.end_date, 
         'state': e.state, 'district': e.city, 'description': e.description, 
         'image_url': e.image_url} for e in all_events
    ]
    return jsonify(events_list), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)


