from flask import Flask, render_template, request, redirect, url_for, g
import sqlite3
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['DATABASE'] = os.path.join(app.root_path, 'team_planner.db')

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
        db.commit()

# Close database connection
@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

# ... [Rest of the Flask routes from previous answer] ...

@app.route('/users', methods=['GET', 'POST'])
def users():
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
def delete_user(user_id):
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return redirect(url_for('users'))

@app.route('/projects', methods=['GET', 'POST'])
def projects():
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
def start_project(project_id):
    db = get_db()
    db.execute('UPDATE projects SET status = "Started" WHERE id = ?', (project_id,))
    db.commit()
    return redirect(url_for('projects'))

@app.route('/close_project/<int:project_id>')
def close_project(project_id):
    db = get_db()
    db.execute('UPDATE projects SET status = "Closed" WHERE id = ?', (project_id,))
    db.commit()
    return redirect(url_for('projects'))

@app.route('/assign', methods=['GET', 'POST'])
def assign():
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
def resource_allocation():
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
def dashboard():
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