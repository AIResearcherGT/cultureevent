from app import db, Organization, app

organizations = [
    {"name": "Archaeological Survey of India (ASI)", "type": "Attached/Subordinate Office", "location": "Delhi", "web_portal": "https://asi.nic.in"},
    {"name": "Anthropological Survey of India (AnSI)", "type": "Attached/Subordinate Office", "location": "West Bengal", "web_portal": "https://ansi.gov.in"},
    {"name": "National Archives of India (NAI)", "type": "Attached/Subordinate Office", "location": "Delhi", "web_portal": "https://nationalarchives.nic.in"},
    {"name": "National Library of India", "type": "Attached/Subordinate Office", "location": "West Bengal", "web_portal": "http://nationallibrary.gov.in"},
    {"name": "Central Secretariat Library (CSL)", "type": "Attached/Subordinate Office", "location": "Delhi", "web_portal": "http://www.csl.nic.in"},
    {"name": "Central Reference Library (CRL)", "type": "Attached/Subordinate Office", "location": "West Bengal", "web_portal": "http://www.crlindia.gov.in"},
    {"name": "Sangeet Natak Akademi (SNA)", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://www.sangeetnatak.gov.in"},
    {"name": "Sahitya Akademi", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://sahitya-akademi.gov.in"},
    {"name": "National School of Drama (NSD)", "type": "Autonomous Body", "location": "Delhi", "web_portal": "https://nsd.gov.in"},
    {"name": "Lalit Kala Akademi (LKA)", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://www.lalitkala.gov.in"},
    {"name": "Centre for Cultural Resources and Training (CCRT)", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://www.ccrtindia.gov.in"},
    {"name": "Indira Gandhi National Centre for the Arts (IGNCA)", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://ignca.gov.in"},
    {"name": "Kalakshetra Foundation", "type": "Autonomous Body", "location": "Tamil Nadu", "web_portal": "http://kalakshetra.in"},
    {"name": "National Gallery of Modern Art (NGMA)", "type": "Autonomous Body", "location": "Delhi, Bangalore", "web_portal": "http://ngmaindia.gov.in"},
    {"name": "Indira Gandhi Rashtriya Manav Sangrahalaya (IGRMS)", "type": "Autonomous Body", "location": "Madhya Pradesh", "web_portal": "http://igrms.gov.in"},
    {"name": "Indian Museum", "type": "Autonomous Body", "location": "West Bengal", "web_portal": "http://indianmuseumkolkata.org"},
    {"name": "National Museum", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://nationalmuseumindia.gov.in"},
    {"name": "National Council of Science Museums (NCSM)", "type": "Autonomous Body", "location": "West Bengal", "web_portal": "http://ncsm.gov.in"},
    {"name": "Central Institute of Buddhist Studies (CIBS)", "type": "Autonomous Body", "location": "Jammu and Kashmir", "web_portal": "http://cibs.ac.in"},
    {"name": "Central Institute of Higher Tibetan Studies (CIHTS)", "type": "Autonomous Body", "location": "Uttar Pradesh", "web_portal": "http://cihts.ac.in"},
    {"name": "Central Institute of Himalayan Culture Studies (CIHCS)", "type": "Autonomous Body", "location": "Arunachal Pradesh", "web_portal": "http://cibhs.org.in"},
    {"name": "National Mission for Manuscripts", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://namami.gov.in"},
    {"name": "National Mission on Monuments and Antiquities", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://nmma.nic.in"},
    {"name": "National Monuments Authority", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://nationalmonumentsauthority.nic.in"},
    {"name": "Maulana Abul Kalam Azad Institute of Asian Studies", "type": "Autonomous Body", "location": "West Bengal", "web_portal": "http://makaias.gov.in"},
    {"name": "Khuda Bakhsh Oriental Public Library", "type": "Autonomous Body", "location": "Bihar", "web_portal": "http://kblibrary.bih.nic.in"},
    {"name": "Gandhi Smriti and Darshan Samiti (GSDS)", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://gandhismriti.gov.in"},
    {"name": "Allahabad Museum", "type": "Autonomous Body", "location": "Uttar Pradesh", "web_portal": "http://theallahabadmuseum.com"},
    {"name": "Salar Jung Museum", "type": "Autonomous Body", "location": "Telangana", "web_portal": "http://salarjungmuseum.in"},
    {"name": "Nehru Memorial Museum and Library (NMML)", "type": "Autonomous Body", "location": "Delhi", "web_portal": "http://nehrumemorial.nic.in"},
    {"name": "Victoria Memorial Hall", "type": "Autonomous Body", "location": "West Bengal", "web_portal": "http://victoriamemorial-cal.org"},
    {"name": "Rampur Raza Library", "type": "Autonomous Body", "location": "Uttar Pradesh", "web_portal": "http://razalibrary.gov.in"},
    {"name": "Asiatic Society", "type": "Autonomous Body", "location": "West Bengal", "web_portal": "http://asiaticsocietykolkata.org"},
    {"name": "Raja Ram Mohan Roy Library Foundation", "type": "Autonomous Body", "location": "West Bengal", "web_portal": "http://rrrlf.nic.in"},
    {"name": "Eastern Zonal Cultural Centre (EZCC)", "type": "Zonal Cultural Centre", "location": "Kolkata", "web_portal": "http://ezccindia.org"},
    {"name": "North Central Zone Cultural Centre (NCZCC)", "type": "Zonal Cultural Centre", "location": "Allahabad", "web_portal": "http://nczccindia.in"},
    {"name": "North East Zone Cultural Centre (NEZCC)", "type": "Zonal Cultural Centre", "location": "Dimapur", "web_portal": "http://nezccindia.org"},
    {"name": "North Zone Cultural Centre (NZCC)", "type": "Zonal Cultural Centre", "location": "Patiala", "web_portal": "http://nzccindia.in"},
    {"name": "South Central Zone Cultural Centre (SCZCC)", "type": "Zonal Cultural Centre", "location": "Nagpur", "web_portal": "http://sczcc.gov.in"},
    {"name": "South Zone Cultural Centre (SZCC)", "type": "Zonal Cultural Centre", "location": "Thanjavur", "web_portal": "http://szccindia.org"},
    {"name": "West Zone Cultural Centre (WZCC)", "type": "Zonal Cultural Centre", "location": "Udaipur", "web_portal": "http://wzccindia.com"}
]

with app.app_context():
    db.session.bulk_insert_mappings(Organization, organizations)
    db.session.commit()

print("Organizations inserted successfully.")
