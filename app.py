from flask import Flask, render_template, request, redirect, url_for, g, make_response, flash
import sqlite3
import os
from datetime import datetime, timedelta
import jwt
import bcrypt
import math
import random
import string

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

@app.route('/logout', methods=['POST'])
def logout():
    # Add your logout logic here (clear session, etc.)
    return redirect(url_for('login'))

@app.route('/admin-users', methods=['GET', 'POST'])
@token_required
def admin_users(current_user):
    db = get_db()
    
    if request.method == 'POST':
        # Check if this is an update request
        if 'user_id' in request.form:
            user_id = request.form['user_id']
            new_password = generate_password_hash(request.form['password'])
            
            db.execute('''
                UPDATE AdminUser 
                SET password = ?
                WHERE id = ?
            ''', (new_password, user_id))
            db.commit()
        else:
            # Existing create new user logic
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
            INSERT INTO users (username, department, status)
            VALUES (?, ?, 'active')
        ''', (username, department))
        db.commit()
    
    # Get department filter from query parameters
    dept_filter = request.args.get('dept_filter', '')
    
    # Build query based on filter
    if dept_filter:
        users = db.execute('SELECT * FROM users WHERE department = ?', (dept_filter,)).fetchall()
    else:
        users = db.execute('SELECT * FROM users').fetchall()
    
    # Get distinct departments for filter dropdown
    departments = db.execute('SELECT DISTINCT department FROM users').fetchall()
    
    return render_template('users.html', users=users, departments=departments, current_dept=dept_filter)

@app.route('/delete_user/<int:user_id>')
@token_required
def delete_user(current_user, user_id):
    db = get_db()
    # Check if user has any assignments
    assignment_count = db.execute(
        'SELECT COUNT(*) FROM user_projects WHERE user_id = ?', 
        (user_id,)
    ).fetchone()[0]
    
    if assignment_count > 0:
        flash('Cannot delete user: User has active assignments', 'error')
        return redirect(url_for('users'))
    
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash('User deleted successfully', 'success')
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
        return redirect(url_for('assign'))

    # Get filter parameters from request
    user_filter = request.args.get('user_filter', '')
    project_filter = request.args.get('project_filter', '')

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10

    # Base query for assignments
    query = '''
        SELECT user_projects.id, users.username, projects.name as project_name,
               user_projects.start_date, user_projects.end_date
        FROM user_projects
        JOIN users ON user_projects.user_id = users.id
        JOIN projects ON user_projects.project_id = projects.id
    '''

    # Build WHERE clause for filters
    conditions = []
    params = []

    if user_filter:
        conditions.append('user_projects.user_id = ?')
        params.append(user_filter)
    if project_filter:
        conditions.append('user_projects.project_id = ?')
        params.append(project_filter)

    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)

    # Count total assignments (for pagination)
    count_query = 'SELECT COUNT(*) FROM user_projects'
    if conditions:
        count_query += ' WHERE ' + ' AND '.join(conditions)
    total_assignments = db.execute(count_query, params).fetchone()[0]
    total_pages = math.ceil(total_assignments / per_page)

    # Add ordering and pagination to the main query
    query += ' ORDER BY user_projects.start_date DESC'
    query += ' LIMIT ? OFFSET ?'
    params.extend([per_page, (page-1)*per_page])

    assignments = db.execute(query, params).fetchall()

    # Only show active users for new assignments
    users = db.execute('SELECT * FROM users WHERE status = "active"').fetchall()
    projects = db.execute('SELECT * FROM projects WHERE status = "Started"').fetchall()
    return render_template('assignments.html', 
                         users=users, 
                         projects=projects,
                         assignments=assignments,
                         page=page,
                         total_pages=total_pages,
                         user_filter=user_filter,
                         project_filter=project_filter)

@app.route('/edit_assignment/<int:assignment_id>', methods=['GET', 'POST'])
@token_required
def edit_assignment(current_user, assignment_id):
    db = get_db()
    assignment = db.execute('''
        SELECT user_projects.*, users.username, projects.name as project_name
        FROM user_projects
        JOIN users ON user_projects.user_id = users.id
        JOIN projects ON user_projects.project_id = projects.id
        WHERE user_projects.id = ?
    ''', (assignment_id,)).fetchone()

    if request.method == 'POST':
        db.execute('''
            UPDATE user_projects 
            SET start_date = ?, end_date = ?
            WHERE id = ?
        ''', (
            request.form['start_date'],
            request.form['end_date'],
            assignment_id
        ))
        db.commit()
        return redirect(url_for('assign'))

    users = db.execute('SELECT * FROM users').fetchall()
    projects = db.execute('SELECT * FROM projects').fetchall()
    return render_template('edit_assignment.html',
                         assignment=assignment,
                         users=users,
                         projects=projects)

@app.route('/resource-allocation')
@token_required
def resource_allocation(current_user):
    db = get_db()
    
    assignments = db.execute('''
        SELECT users.id as user_id, users.username, users.department,
               projects.id as project_id, projects.name, projects.color,
               user_projects.start_date, user_projects.end_date 
        FROM user_projects
        JOIN users ON user_projects.user_id = users.id
        JOIN projects ON user_projects.project_id = projects.id
        WHERE users.status = 'active'
        ORDER BY users.username, user_projects.start_date
    ''').fetchall()

    # Group tasks by user
    users = {}
    for assignment in assignments:
        user_id = assignment['user_id']
        if user_id not in users:
            users[user_id] = {
                'name': assignment['username'],
                'department': assignment['department'],
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

    # Get project timeline data
    assignments = db.execute('''
        SELECT 
            projects.id as project_id,
            projects.name,
            projects.color,
            user_projects.start_date,
            user_projects.end_date
        FROM user_projects
        JOIN projects ON user_projects.project_id = projects.id
    ''').fetchall()

    from collections import defaultdict
    from datetime import datetime, timedelta

    project_timelines = defaultdict(list)
    all_dates = set()

    # Process assignments to get daily hours
    for assignment in assignments:
        project = dict(assignment)
        start = datetime.strptime(project['start_date'], '%Y-%m-%d').date()
        end = datetime.strptime(project['end_date'], '%Y-%m-%d').date()
        
        # Generate all dates in this assignment range
        delta = end - start
        for i in range(delta.days + 1):
            current_date = start + timedelta(days=i)
            all_dates.add(current_date)
            project_timelines[project['name']].append(current_date)

    # Create sorted list of all unique dates
    date_sequence = sorted(all_dates)
    
    # Create a dictionary of project colors
    project_colors = {project['name']: project['color'] for project in assignments}

    # Prepare chart data
    hours_datasets = []
    for project, dates in project_timelines.items():
        color = project_colors.get(project, '#3B82F6')  # Default to blue if missing
        date_counts = {date: 0 for date in date_sequence}
        
        # Count hours per day (8 per developer)
        for d in dates:
            date_counts[d] += 8
        
        hours_datasets.append({
            'label': project,
            'data': [date_counts[date] for date in date_sequence],
            'borderColor': color,
            'tension': 0.4,
            'fill': False
        })

    # Convert dates to ISO strings for JSON serialization
    date_sequence = [date.isoformat() for date in sorted(all_dates)]
    
    # Calculate resource utilization for next 30 days
    today = datetime.today().date()
    end_date = today + timedelta(days=30)
    
    # Calculate total weekdays in next 30 days
    total_weekdays = sum(1 for i in range(31) 
                      if (today + timedelta(days=i)).weekday() < 5)
    
    # Get all assignments within next 30 days - only for active users
    assignments = db.execute('''
        SELECT users.id, users.username, 
               user_projects.start_date, user_projects.end_date
        FROM user_projects
        JOIN users ON user_projects.user_id = users.id
        WHERE user_projects.start_date <= ? 
          AND user_projects.end_date >= ?
          AND users.status = 'active'  -- Only include active users
    ''', (end_date.isoformat(), today.isoformat())).fetchall()
    
    # Calculate utilization per user - only for active users
    user_utilization = {}
    for user in db.execute('SELECT id, username, department FROM users WHERE status = "active"').fetchall():
        user_utilization[user['id']] = {
            'username': user['username'],
            'department': user['department'],
            'assigned_days': 0,
            'next_available': None
        }

    for assignment in assignments:
        user_id = assignment['id']
        start = max(today, datetime.strptime(assignment['start_date'], '%Y-%m-%d').date())
        end = min(end_date, datetime.strptime(assignment['end_date'], '%Y-%m-%d').date())
        
        # Count assigned weekdays
        assigned_days = sum(1 for i in range((end - start).days + 1)
                         if (start + timedelta(days=i)).weekday() < 5)
        
        user_utilization[user_id]['assigned_days'] += assigned_days
        
        # Update next available date if this assignment ends later
        if user_utilization[user_id]['next_available'] is None or end > user_utilization[user_id]['next_available']:
            # Add 1 day to the end date to get next available
            next_avail = end + timedelta(days=1)
            # Skip weekends
            while next_avail.weekday() >= 5:  # 5=Saturday, 6=Sunday
                next_avail += timedelta(days=1)
            user_utilization[user_id]['next_available'] = next_avail

    # Calculate utilization percentage
    utilisation_data = []
    for user_id, data in user_utilization.items():
        utilisation = (data['assigned_days'] * 100) / total_weekdays if total_weekdays > 0 else 0
        next_avail = data['next_available'] or today  # Use today if no assignments
        
        # Show "-" if not available in next 30 days
        if next_avail > end_date:
            next_avail_str = '-'
        else:
            next_avail_str = next_avail.strftime('%Y-%m-%d')

        utilisation_data.append({
            'username': data['username'],
            'department': data['department'],
            'utilisation': round(utilisation, 2),
            'next_available': next_avail_str  # Use formatted string
        })
    
    # Get department filter from request
    dept_filter = request.args.get('dept_filter', '')
    
    # Apply department filter
    if dept_filter:
        utilisation_data = [u for u in utilisation_data if u['department'] == dept_filter]
    
    # Sorting and pagination parameters
    sort_by = request.args.get('sort', 'utilisation')
    sort_order = request.args.get('order', 'asc')
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Items per page

    # Sort utilisation data
    reverse_order = sort_order == 'desc'
    if sort_by == 'username':
        utilisation_data.sort(key=lambda x: x['username'], reverse=reverse_order)
    elif sort_by == 'department':
        utilisation_data.sort(key=lambda x: x['department'], reverse=reverse_order)
    elif sort_by == 'next_available':
        utilisation_data.sort(key=lambda x: x['next_available'], reverse=reverse_order)
    else:  # Default sort by utilisation
        utilisation_data.sort(key=lambda x: x['utilisation'], reverse=reverse_order)

    # Pagination
    total_items = len(utilisation_data)
    total_pages = (total_items + per_page - 1) // per_page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_data = utilisation_data[start_idx:end_idx]

    return render_template('dashboard.html', 
                         active_projects=active_projects,
                         closed_projects=closed_projects,
                         queued_projects=queued_projects,
                         total_projects=total_projects,
                         total_users=total_users,
                         department_data=department_data,
                         project_allocation_data=project_allocation_data,
                         date_sequence=date_sequence,
                         hours_datasets=hours_datasets,
                         utilisation_data=paginated_data,
                         total_weekdays=total_weekdays,
                         sort_by=sort_by,
                         sort_order=sort_order,
                         current_page=page,
                         total_pages=total_pages,
                         total_items=total_items,
                         dept_filter=dept_filter)

@app.route('/delete_assignment/<int:assignment_id>')
@token_required
def delete_assignment(current_user, assignment_id):
    db = get_db()
    db.execute('DELETE FROM user_projects WHERE id = ?', (assignment_id,))
    db.commit()
    return redirect(url_for('assign'))

@app.route('/edit_project/<int:project_id>', methods=['GET', 'POST'])
@token_required
def edit_project(current_user, project_id):
    db = get_db()
    project = db.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        color = request.form['color']
        
        db.execute('''
            UPDATE projects 
            SET name = ?, description = ?, color = ?
            WHERE id = ?
        ''', (name, description, color, project_id))
        db.commit()
        return redirect(url_for('projects'))
    
    return render_template('edit_project.html', project=project)

@app.route('/delete_project/<int:project_id>')
@token_required
def delete_project(current_user, project_id):
    db = get_db()
    # Check if project has any assignments
    assignment_count = db.execute(
        'SELECT COUNT(*) FROM user_projects WHERE project_id = ?', 
        (project_id,)
    ).fetchone()[0]
    
    if assignment_count > 0:
        flash('Cannot delete project: Project has active assignments', 'error')
        return redirect(url_for('projects'))
    
    # Delete the project
    db.execute('DELETE FROM projects WHERE id = ?', (project_id,))
    db.commit()
    flash('Project deleted successfully', 'success')
    return redirect(url_for('projects'))


@app.route('/toggle_user_status/<int:user_id>')
@token_required
def toggle_user_status(current_user, user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('users'))
    
    new_status = 'inactive' if user['status'] == 'active' else 'active'
    db.execute('UPDATE users SET status = ? WHERE id = ?', (new_status, user_id))
    db.commit()
    flash(f'User status changed to {new_status}', 'success')
    return redirect(url_for('users'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@token_required
def edit_user(current_user, user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('users'))
    if request.method == 'POST':
        username = request.form['username']
        department = request.form['department']
        status = request.form['status']
        db.execute(
            'UPDATE users SET username = ?, department = ?, status = ? WHERE id = ?',
            (username, department, status, user_id)
        )
        db.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('users'))
    return render_template('edit_user.html', user=user) 

def generate_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password_hash(hashed, password):
    # Only try bcrypt if the hash looks like a bcrypt hash
    if not (hashed.startswith('$2a$') or hashed.startswith('$2b$') or hashed.startswith('$2y$')):
        # Not a bcrypt hash, always fail (or handle migration)
        return False
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# python -c "from app import reset_admin_passwords; reset_admin_passwords()"
def reset_admin_passwords():
    """Update all AdminUser passwords to random ones and print them."""
    with app.app_context():
        db = get_db()
        users = db.execute('SELECT id, username FROM AdminUser').fetchall()
        print("Resetting admin passwords:")
        for user in users:
            # Generate a random 10-character password
            new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            hashed = generate_password_hash(new_password)
            db.execute('UPDATE AdminUser SET password = ? WHERE id = ?', (hashed, user['id']))
            print(f"Username: {user['username']}, New Password: {new_password}")
        db.commit()
        print("All admin passwords have been reset.")

# New salary management routes
@app.route('/salaries', methods=['GET', 'POST'])
@token_required
def salaries(current_user):
    db = get_db()
    
    if request.method == 'POST':
        user_id = request.form['user_id']
        salary = request.form['salary']
        effective_date = request.form['effective_date']
        
        db.execute('''
            INSERT INTO salaries (user_id, salary, effective_date)
            VALUES (?, ?, ?)
        ''', (user_id, salary, effective_date))
        db.commit()
        flash('Salary added successfully', 'success')
    
    # Get all salaries with user names
    salaries = db.execute('''
        SELECT salaries.id, salaries.user_id, salaries.salary, salaries.effective_date, users.username 
        FROM salaries
        JOIN users ON salaries.user_id = users.id
        ORDER BY salaries.effective_date DESC
    ''').fetchall()
    
    users = db.execute('SELECT * FROM users').fetchall()
    return render_template('salaries.html', salaries=salaries, users=users)

@app.route('/delete_salary/<int:salary_id>')
@token_required
def delete_salary(current_user, salary_id):
    db = get_db()
    db.execute('DELETE FROM salaries WHERE id = ?', (salary_id,))
    db.commit()
    flash('Salary record deleted successfully', 'success')
    return redirect(url_for('salaries'))

# Add custom filter for template
@app.template_filter('string_to_date')
def string_to_date(s):
    return datetime.strptime(s, '%Y-%m-%d').date() 

@app.route('/project-costs')
@token_required
def project_costs(current_user):
    db = get_db()
    
    # Get all projects
    projects = db.execute('SELECT * FROM projects').fetchall()
    
    # Get all assignments
    assignments = db.execute('''
        SELECT user_projects.*, users.username, projects.name as project_name
        FROM user_projects
        JOIN users ON user_projects.user_id = users.id
        JOIN projects ON user_projects.project_id = projects.id
    ''').fetchall()
    
    # Get all salaries (latest salary per user)
    salaries = {}
    for row in db.execute('''
        SELECT s1.* 
        FROM salaries s1
        LEFT JOIN salaries s2 
            ON s1.user_id = s2.user_id 
            AND s1.effective_date < s2.effective_date
        WHERE s2.id IS NULL
    ''').fetchall():
        salaries[row['user_id']] = row['salary']
    
    # Calculate costs for each project
    project_costs = {}
    for project in projects:
        project_costs[project['id']] = {
            'name': project['name'],
            'status': project['status'],
            'current_cost': 0.0,
            'estimated_cost': 0.0
        }
    
    # Helper function to calculate business days
    def business_days(start, end):
        days = (end - start).days + 1
        full_weeks = days // 7
        extra_days = days % 7
        business_days = full_weeks * 5
        # Add extra days excluding weekends
        for i in range(extra_days):
            if (start + timedelta(days=i)).weekday() < 5:
                business_days += 1
        return business_days
    
    today = datetime.today().date()
    
    for assignment in assignments:
        start_date = datetime.strptime(assignment['start_date'], '%Y-%m-%d').date()
        end_date = datetime.strptime(assignment['end_date'], '%Y-%m-%d').date()
        
        # Get user's salary
        salary = salaries.get(assignment['user_id'], 0)
        
        # Calculate daily rate (assuming 22 working days/month)
        daily_rate = salary / 22 if salary else 0
        
        # Calculate total business days in assignment
        total_days = business_days(start_date, end_date)
        
        # Calculate actual days worked so far
        if today < start_date:
            actual_days = 0
        elif today > end_date:
            actual_days = total_days
        else:
            actual_days = business_days(start_date, today)
        
        # Calculate costs
        current_cost = actual_days * daily_rate
        estimated_cost = total_days * daily_rate
        
        # Add to project totals
        project_id = assignment['project_id']
        project_costs[project_id]['current_cost'] += current_cost
        project_costs[project_id]['estimated_cost'] += estimated_cost
    
    return render_template('project_costing.html', 
                         projects=project_costs.values(),
                         currency=currency_filter)

# Add this after the existing template filter
@app.template_filter('currency')
def currency_filter(value):
    return '${:,.2f}'.format(value)
def migrate_db():
    with app.app_context():
        db = get_db()
        # Check if status column exists
        cursor = db.execute("PRAGMA table_info(users)")
        columns = [row['name'] for row in cursor.fetchall()]
        if 'status' not in columns:
            db.execute('ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT "active"')
            db.commit()

# Run migration at startup
with app.app_context():
    migrate_db()

if __name__ == '__main__':
    app.run(debug=True) 