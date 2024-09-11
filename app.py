from flask import Flask, request, jsonify, render_template, redirect, url_for, Response, flash
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base
from bs4 import BeautifulSoup
import requests
from datetime import datetime
import json
import time

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Required for flashing messages

# Configuration de la base de données SQLite
SQLALCHEMY_DATABASE_URL = "sqlite:///queries.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
Base = declarative_base()
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

############################################################

# Model for storing reports (StopRansomware reports)
class ReportModel(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    url = Column(String, nullable=False)
    date = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

# Function to scrape and extract #StopRansomware titles, URLs, and dates from each article
def extract_stop_ransomware_articles(url):
    response = requests.get(url)
    time.sleep(2)
    response.raise_for_status()  # Raise an error for bad responses
    soup = BeautifulSoup(response.text, 'html.parser')
    articles = soup.find_all('article', class_='is-promoted c-teaser c-teaser--horizontal')
    extracted_articles = []
    
    for article in articles:
        title_link = article.find('h3', class_='c-teaser__title').find('a')
        title_span = title_link.find('span')
        if title_span:
            title_text = title_span.text.strip()
            if title_text.startswith('#StopRansomware:'):
                article_url = title_link['href']
                full_url = f"https://www.cisa.gov{article_url}" if article_url.startswith('/') else article_url
                date_div = article.find('div', class_='c-teaser__date')
                article_date = date_div.find('time').text.strip() if date_div else 'Unknown Date'
                extracted_articles.append({'title': title_text, 'url': full_url, 'date': article_date})
    return extracted_articles

# Function to search and scrape reports for all pages
def scrape_reports():
    db = SessionLocal()
    for page_number in range(20):
        url = f"https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94&page={page_number}"
        response = requests.get(url)
        if response.status_code == 200:
            articles = extract_stop_ransomware_articles(url)
            for article in articles:
                # Check if the report already exists in the database
                existing_report = db.query(ReportModel).filter_by(url=article['url']).first()
                if not existing_report:
                    # Insert the report into the database
                    new_report = ReportModel(
                        title=article['title'],
                        url=article['url'],
                        date=article['date']
                    )
                    db.add(new_report)
            db.commit()
        else:
            break

# Route to manually trigger the scraping
@app.route('/scrape-reports', methods=['GET'])
def scrape_reports_route():
    scrape_reports()
    flash('Reports scraped successfully!')
    return redirect(url_for('list_reports'))

# Route to list all existing reports
@app.route('/list-reports', methods=['GET'])
def list_reports():
    db = SessionLocal()
    reports = db.query(ReportModel).all()
    return render_template('list_reports.html', reports=reports)



############################################################

# Modèle de base de données pour stocker les requêtes
class QueryModel(Base):
    __tablename__ = "queries"

    id = Column(Integer, primary_key=True, index=True)
    query = Column(Text, nullable=False)
    tag = Column(String, index=True)
    query_type = Column(String, nullable=False)  # Stocker le type de requête (domain, hash, filename)
    category = Column(String, nullable=False)    # Stocker la catégorie (XQL, Splunk)

# Modèle pour stocker l'historique des exécutions
class ExecutionHistory(Base):
    __tablename__ = "execution_history"
    
    id = Column(Integer, primary_key=True, index=True)
    report_url = Column(String, nullable=False)  # Lien du rapport soumis
    query_id = Column(Integer, nullable=False)   # ID de la requête exécutée
    final_query = Column(Text, nullable=False)   # La requête finale exécutée
    campaign_title = Column(String, nullable=True) # Titre du rapport (nom de la campagne)
    category = Column(String, nullable=False)        # Catégorie de la requête (XQL ou Splunk)
    execution_time = Column(String, default=datetime.utcnow)  # Date et heure d'exécution

# Création des tables
Base.metadata.create_all(bind=engine)

# Fonction pour défanger les URLs et adresses IP
def defang(text):
    return text.replace('[.]', '.').replace('[:]', ':').replace('[]', '')

# Fonction pour extraire des données à partir d'un tableau dans le rapport
def extract_data_from_table(soup, header_name):
    header = soup.find('th', string=header_name)
    if header:
        table = header.find_parent('table')
        if table:
            td_tags = table.find_all('td')
            data = []
            for td in td_tags:
                a_tag = td.find('a')
                if a_tag and a_tag.get('href'):
                    data.append(a_tag['href'])
                elif td.string:
                    data.append(td.string.strip())
            return data
    return []

# Page d'accueil
@app.route('/')
def index():
    return render_template('index.html')

# Page HTML pour soumettre une nouvelle requête
@app.route('/store-query', methods=['GET', 'POST'])
def store_query():
    db = SessionLocal()
    if request.method == 'POST':
        query = request.form['query']
        tag = request.form['tag']
        query_type = request.form['query_type']
        category = request.form['category'] 
        new_query = QueryModel(query=query, tag=tag, query_type=query_type, category=category)
        db.add(new_query)
        db.commit()
        return jsonify({"message": "Requête stockée avec succès", "query_id": new_query.id})
    return render_template('store_query.html')


# Route for exporting stored requests in JSON format
@app.route('/export-queries', methods=['GET'])
def export_queries():
    db = SessionLocal()
    queries = db.query(QueryModel).all()

    # Create a list of dictionaries from the stored queries
    query_list = [
        {
            "id": query.id,
            "query": query.query,
            "tag": query.tag,
            "query_type": query.query_type,
            "category": query.category
        }
        for query in queries
    ]

    # Convert the list to JSON
    json_data = json.dumps(query_list, indent=4)

    # Create a Response object with the appropriate content type and headers for download
    response = Response(json_data, mimetype='application/json')
    response.headers['Content-Disposition'] = 'attachment;filename=queries.json'

    return response


# Route for importing requests from JSON
@app.route('/import-queries', methods=['GET', 'POST'])
def import_queries():
    if request.method == 'POST':
        if 'json_file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        json_file = request.files['json_file']

        # If the user does not select a file, browser submits an empty file without a filename
        if json_file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if json_file and json_file.filename.endswith('.json'):
            try:
                # Read and parse the JSON file
                json_data = json.load(json_file)

                # Validate and insert each query into the database
                db = SessionLocal()
                for query_data in json_data:
                    # Ensure all required fields are present
                    if all(key in query_data for key in ('query', 'tag', 'query_type', 'category')):
                        new_query = QueryModel(
                            query=query_data['query'],
                            tag=query_data['tag'],
                            query_type=query_data['query_type'],
                            category=query_data['category']
                        )
                        db.add(new_query)
                    else:
                        flash('Invalid JSON format in some entries.')
                        return redirect(request.url)

                db.commit()
                flash('Queries imported successfully.')
            except Exception as e:
                flash(f'Error while importing JSON: {str(e)}')
            return redirect(url_for('list_queries'))

    return render_template('import_queries.html')



# Page pour lister toutes les requêtes stockées
@app.route('/queries', methods=['GET'])
def list_queries():
    db = SessionLocal()
    queries = db.query(QueryModel).all()
    return render_template('list_queries.html', queries=queries)

# Page pour mettre à jour une requête existante
@app.route('/update-query/<int:query_id>', methods=['GET', 'POST'])
def update_query(query_id):
    db = SessionLocal()
    query_to_update = db.query(QueryModel).filter_by(id=query_id).first()
    if not query_to_update:
        return jsonify({"error": "Requête non trouvée"}), 404
    
    if request.method == 'POST':
        query_to_update.query = request.form['query']
        query_to_update.tag = request.form['tag']
        query_to_update.query_type = request.form['query_type']
        db.commit()
        return redirect(url_for('list_queries'))
    
    return render_template('update_query.html', query=query_to_update)

# Page pour exécuter les requêtes automatiquement selon les données extraites
@app.route('/execute-query', methods=['GET', 'POST'])
def execute_query():
    db = SessionLocal()
    if request.method == 'POST':
        url = request.form['url']
        try:
            # Récupérer les données du rapport à partir de l'URL
            response = requests.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            campaign_title = soup.title.string if soup.title else "Titre non disponible"
            

            # Extraire les données (domain, hash, filename)
            domains = extract_data_from_table(soup, 'Domain')
            hashes = extract_data_from_table(soup, 'Hash')
            filenames = extract_data_from_table(soup, 'Filename')

            # Parcourir les requêtes et trouver celles correspondant aux données extraites
            relevant_queries = []

            if domains:
                queries_for_domain = db.query(QueryModel).filter(QueryModel.query_type == "domain").all()
                relevant_queries += queries_for_domain

            if hashes:
                queries_for_hash = db.query(QueryModel).filter(QueryModel.query_type == "hash").all()
                relevant_queries += queries_for_hash

            if filenames:
                queries_for_filename = db.query(QueryModel).filter(QueryModel.query_type == "filename").all()
                relevant_queries += queries_for_filename

            # Exécuter toutes les requêtes pertinentes
            executed_queries = []
            for query in relevant_queries:
                if "$1" in query.query:
                    if query.query_type == "domain":
                        data_list = '|'.join([defang(domain) for domain in domains])
                    elif query.query_type == "hash":
                        data_list = '|'.join([defang(hash) for hash in hashes])
                    elif query.query_type == "filename":
                        data_list = '|'.join([defang(filename) for filename in filenames])
                    query_with_data = query.query.replace("$1", data_list)
                    executed_queries.append({"query_id": query.id, "final_query": query_with_data})

                    # Enregistrer l'exécution dans l'historique
                    execution = ExecutionHistory(
                        report_url=url,
                        query_id=query.id,
                        final_query=query_with_data,
                        campaign_title=campaign_title,
                        category=query.category
                    )
                    db.add(execution)
                    db.commit()

            # Afficher l'URL du rapport soumis avec les requêtes exécutées
            if executed_queries:
                return render_template('execute_query.html', executed_queries=executed_queries, report_url=url, campaign_title=campaign_title)
            else:
                return jsonify({"message": "Aucune requête pertinente trouvée pour les données extraites."})

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return render_template('execute_query.html')

# Route pour afficher l'historique des exécutions
@app.route('/history', methods=['GET'])
def history():
    db = SessionLocal()
    executions = db.query(ExecutionHistory).all()
    return render_template('history.html', executions=executions)

# Route pour supprimer une exécution spécifique
@app.route('/delete-execution/<int:execution_id>', methods=['POST'])
def delete_execution(execution_id):
    db = SessionLocal()
    execution_to_delete = db.query(ExecutionHistory).filter_by(id=execution_id).first()
    if not execution_to_delete:
        return jsonify({"error": "Exécution non trouvée"}), 404
    db.delete(execution_to_delete)
    db.commit()
    return redirect(url_for('history'))

# Route pour supprimer tout l'historique
@app.route('/delete-all-history', methods=['POST'])
def delete_all_history():
    db = SessionLocal()
    db.query(ExecutionHistory).delete()
    db.commit()
    return redirect(url_for('history'))

if __name__ == "__main__":
    app.run(debug=True)
