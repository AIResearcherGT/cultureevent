import os
import random
import json
from faker import Faker
from datetime import datetime, timedelta
from app import db, Event, Organization  # Adjust import based on your app structure
from flask import Flask

# Initialize Faker
fake = Faker()

# Ensure the app context is available
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///new_events.db')
db.init_app(app)

# Load state and city data from JSON file
with open('indian_state_city_list.json') as f:
    state_city_data = json.load(f)

# Function to get a random state and a corresponding random city
def get_random_state_city():
    state = random.choice(state_city_data)['State']
    cities = [entry['City'] for entry in state_city_data if entry['State'] == state]
    city = random.choice(cities)
    return state, city

# Example categories and languages
categories = ['Dance', 'Exhibition', 'Fair', 'Fair & Fierce', 'Paint & Sketching', 'Talk & Music', 'Theatre']
languages = ['English', 'Hindi']

# List of organizations
organizations_list = [
    (1, "Archaeological Survey of India (ASI)"),
    (2, "Anthropological Survey of India (AnSI)"),
    (3, "National Archives of India (NAI)"),
    (4, "National Library of India"),
    (5, "Central Secretariat Library (CSL)"),
    (6, "Central Reference Library (CRL)"),
    (7, "Sangeet Natak Akademi (SNA)"),
    (8, "Sahitya Akademi"),
    (9, "National School of Drama (NSD)"),
    (10, "Lalit Kala Akademi (LKA)"),
    (11, "Centre for Cultural Resources and Training (CCRT)"),
    (12, "Indira Gandhi National Centre for the Arts (IGNCA)"),
    (13, "Kalakshetra Foundation"),
    (14, "National Gallery of Modern Art (NGMA)"),
    (15, "Indira Gandhi Rashtriya Manav Sangrahalaya (IGRMS)"),
    (16, "Indian Museum"),
    (17, "National Museum"),
    (18, "National Council of Science Museums (NCSM)"),
    (19, "Central Institute of Buddhist Studies (CIBS)"),
    (20, "Central Institute of Higher Tibetan Studies (CIHTS)"),
    (21, "Central Institute of Himalayan Culture Studies (CIHCS)"),
    (22, "National Mission for Manuscripts"),
    (23, "National Mission on Monuments and Antiquities"),
    (24, "National Monuments Authority"),
    (25, "Maulana Abul Kalam Azad Institute of Asian Studies"),
    (26, "Khuda Bakhsh Oriental Public Library"),
    (27, "Gandhi Smriti and Darshan Samiti (GSDS)"),
    (28, "Allahabad Museum"),
    (29, "Salar Jung Museum"),
    (30, "Nehru Memorial Museum and Library (NMML)"),
    (31, "Victoria Memorial Hall"),
    (32, "Rampur Raza Library"),
    (33, "Asiatic Society"),
    (34, "Raja Ram Mohan Roy Library Foundation"),
    (35, "Eastern Zonal Cultural Centre (EZCC)"),
    (36, "North Central Zone Cultural Centre (NCZCC)"),
    (37, "North East Zone Cultural Centre (NEZCC)"),
    (38, "North Zone Cultural Centre (NZCC)"),
    (39, "South Central Zone Cultural Centre (SCZCC)"),
    (40, "South Zone Cultural Centre (SZCC)"),
    (41, "West Zone Cultural Centre (WZCC)")
]

def create_organizations():
    organizations = []
    for org_id, org_name in organizations_list:
        existing_org = db.session.get(Organization, org_id)
        if not existing_org:
            organization = Organization(
                id=org_id,
                name=org_name,
                type=random.choice(['Government', 'Non-Profit', 'Corporate']),
                location='India',
                web_portal=fake.url()
            )
            organizations.append(organization)
            db.session.add(organization)
        else:
            organizations.append(existing_org)
    db.session.commit()
    return organizations

def create_events(num, organizations):
    if not organizations:
        print("No organizations available to assign events.")
        return

    for _ in range(num):
        start_date = fake.date_between(start_date='now', end_date='+30d')
        end_date = start_date + timedelta(days=random.randint(1, 3))
        state, city = get_random_state_city()
        event = Event(
            title=fake.catch_phrase(),
            language=random.choice(languages),
            category=random.choice(categories),
            start_date=start_date.strftime('%Y-%m-%d'),
            start_time=fake.time(),
            end_date=end_date.strftime('%Y-%m-%d'),
            end_time=fake.time(),
            state=state,
            city=city,
            venue=fake.address(),
            description=fake.text(max_nb_chars=200),
            image_url=fake.image_url(),
            archive_date=None,
            organization_id=random.choice(organizations).id
        )
        db.session.add(event)
    db.session.commit()

with app.app_context():
    db.create_all()  # Ensure the database and tables are created
    organizations = create_organizations()  # Create the predefined organizations
    create_events(50, organizations)  # Create 50 events with the created organizations

print("Database populated with 50 events.")
