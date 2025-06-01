from flask import Flask, render_template, request, redirect, url_for, g, make_response
import sqlite3
import os
from datetime import datetime, timedelta
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['DATABASE'] = os.path.join(app.root_path, 'team_planner.db')
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production!

# Database initialization
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        # Add initial admin user
        db.execute(
            'INSERT OR IGNORE INTO AdminUser (username, password) VALUES (?, ?)',
            ('admin', generate_password_hash('1234'))
        )
        db.commit()

# Close database connection
@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

def get_admin_user(username):
    db = get_db()
    return db.execute(
        'SELECT * FROM AdminUser WHERE username = ?', (username,)
    ).fetchone()

def token_required(f):
    def decorator(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = get_admin_user(data['username'])
        except:
            return redirect(url_for('login'))
        return f(current_user, *args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_admin_user(username)
        
        if user and check_password_hash(user['password'], password):
            token = jwt.encode({
                'username': user['username'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['SECRET_KEY'])
            
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('token', token)
            return resp
        
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('token')
    return resp

@app.route('/admin-users', methods=['GET', 'POST'])
@token_required
def admin_users(current_user):
    db = get_db()
    
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        
        try:
            db.execute('''
                INSERT INTO AdminUser (username, password)
                VALUES (?, ?)
            ''', (username, password))
            db.commit()
        except sqlite3.IntegrityError:
            return render_template('admin_users.html', error='Username already exists')
    
    users = db.execute('SELECT * FROM AdminUser').fetchall()
    return render_template('admin_users.html', users=users)

@app.route('/users', methods=['GET', 'POST'])
@token_required
def users(current_user):
    db = get_db()
    
    if request.method == 'POST':
        username = request.form['username']
        department = request.form['department']
        
        db.execute('''
            INSERT INTO users (username, department)
            VALUES (?, ?)
        ''', (username, department))
        db.commit()
    
    users = db.execute('SELECT * FROM users').fetchall()
    return render_template('users.html', users=users)

@app.route('/delete_user/<int:user_id>')
@token_required
def delete_user(current_user, user_id):
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('users'))

@app.route('/projects', methods=['GET', 'POST'])
@token_required
def projects(current_user):
    db = get_db()
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        color = request.form['color']
        
        db.execute('''
            INSERT INTO projects (name, description, color, status)
            VALUES (?, ?, ?, 'Queued')
        ''', (name, description, color))
        db.commit()
    
    projects = db.execute('SELECT * FROM projects').fetchall()
    return render_template('projects.html', projects=projects)

@app.route('/start_project/<int:project_id>')
@token_required
def start_project(current_user, project_id):
    db = get_db()
    db.execute('UPDATE projects SET status = "Started" WHERE id = ?', (project_id,))
    db.commit()
    return redirect(url_for('projects'))

@app.route('/close_project/<int:project_id>')
@token_required
def close_project(current_user, project_id):
    db = get_db()
    db.execute('UPDATE projects SET status = "Closed" WHERE id = ?', (project_id,))
    db.commit()
    return redirect(url_for('projects'))

@app.route('/assign', methods=['GET', 'POST'])
@token_required
def assign(current_user):
    db = get_db()
    
    if request.method == 'POST':
        user_id = request.form['user_id']
        project_id = request.form['project_id']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        
        db.execute('''
            INSERT INTO user_projects (user_id, project_id, start_date, end_date)
            VALUES (?, ?, ?, ?)
        ''', (user_id, project_id, start_date, end_date))
        db.commit()
    
    users = db.execute('SELECT * FROM users').fetchall()
    projects = db.execute('SELECT * FROM projects WHERE status = "Started"').fetchall()
    return render_template('assignments.html', users=users, projects=projects)

@app.route('/resource-allocation')
@token_required
def resource_allocation(current_user):
    db = get_db()
    
    assignments = db.execute('''
        SELECT users.id as user_id, users.username, 
               projects.id as project_id, projects.name, projects.color,
               user_projects.start_date, user_projects.end_date 
        FROM user_projects
        JOIN users ON user_projects.user_id = users.id
        JOIN projects ON user_projects.project_id = projects.id
        ORDER BY users.username, user_projects.start_date
    ''').fetchall()

    # Group tasks by user
    users = {}
    for assignment in assignments:
        user_id = assignment['user_id']
        if user_id not in users:
            users[user_id] = {
                'name': assignment['username'],
                'tasks': []
            }
        users[user_id]['tasks'].append({
            'id': f"project_{assignment['project_id']}",
            'name': assignment['name'],
            'start': assignment['start_date'],
            'end': assignment['end_date'],
            'progress': 100,
            'dependencies': '',
            'color': assignment['color']
        })

    # Convert dict_values to list for JSON serialization
    users_list = list(users.values())

    return render_template('resource_allocation.html', users=users_list)

@app.route('/')
@token_required
def dashboard(current_user):
    db = get_db()
    active_projects = db.execute('SELECT COUNT(*) FROM projects WHERE status = "Started"').fetchone()[0]
    closed_projects = db.execute('SELECT COUNT(*) FROM projects WHERE status = "Closed"').fetchone()[0]
    queued_projects = db.execute('SELECT COUNT(*) FROM projects WHERE status = "Queued"').fetchone()[0]
    total_projects = db.execute('SELECT COUNT(*) FROM projects').fetchone()[0]
    total_users = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    department_data = db.execute('''
        SELECT department, COUNT(*) as count 
        FROM users 
        GROUP BY department
    ''').fetchall()
    
    project_allocation_data = db.execute('''
        SELECT projects.name, COUNT(DISTINCT user_id) as user_count
        FROM user_projects
        JOIN projects ON user_projects.project_id = projects.id
        GROUP BY projects.name
    ''').fetchall()

    return render_template('dashboard.html', 
                         active_projects=active_projects,
                         closed_projects=closed_projects,
                         queued_projects=queued_projects,
                         total_projects=total_projects,
                         total_users=total_users,
                         department_data=department_data,
                         project_allocation_data=project_allocation_data)

if __name__ == '__main__':
    app.run(debug=True) 