from flask import Flask, render_template, request, redirect, url_for, g, flash, make_response
import sqlite3
import os
from datetime import datetime, timedelta
import math
import jwt
import bcrypt
import random
import string

app = Flask(__name__, template_folder='templates')
app.config['MAIN_DATABASE'] = os.path.join(app.root_path, 'team_planner.db')
app.config['SALARIES_DATABASE'] = os.path.join(app.root_path, 'salaries.db')
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production!

# Add currency filter to Jinja environment
@app.template_filter('currency')
def currency_filter(value):
    if value is None:
        return '$0.00'  # Handle None values
    return '${:,.2f}'.format(value)

# Password helper functions
def generate_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password_hash(hashed, password):
    if not (hashed.startswith('$2a$') or hashed.startswith('$2b$') or hashed.startswith('$2y$')):
        return False
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# Database connections
def get_main_db():
    if 'main_db' not in g:
        g.main_db = sqlite3.connect(app.config['MAIN_DATABASE'])
        g.main_db.row_factory = sqlite3.Row
    return g.main_db

def get_salaries_db():
    if 'salaries_db' not in g:
        g.salaries_db = sqlite3.connect(app.config['SALARIES_DATABASE'])
        g.salaries_db.row_factory = sqlite3.Row

        # Attach the main database
        main_db_path = app.config['MAIN_DATABASE']
        main_db_path_escaped = main_db_path.replace("'", "''")
        attach_sql = f"ATTACH DATABASE '{main_db_path_escaped}' AS main_db"
        g.salaries_db.execute(attach_sql)

        # Initialize salaries table
        with g.salaries_db:
            g.salaries_db.execute('''
                CREATE TABLE IF NOT EXISTS salaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    salary REAL NOT NULL,
                    effective_date TEXT NOT NULL
                )
            ''')

            # Create project_budgets table
            g.salaries_db.execute('''
                CREATE TABLE IF NOT EXISTS project_budgets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL UNIQUE,
                    budget REAL NOT NULL
                )
            ''')

            # Create project_payments table
            g.salaries_db.execute('''
                CREATE TABLE IF NOT EXISTS project_payments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    amount REAL NOT NULL,
                    payment_date TEXT NOT NULL
                )
            ''')

        # Create AdminUser table in salaries.db
        g.salaries_db.execute('''
            CREATE TABLE IF NOT EXISTS AdminUser (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        # Add initial admin user
        g.salaries_db.execute(
            'INSERT OR IGNORE INTO AdminUser (username, password) VALUES (?, ?)',
            ('admin', generate_password_hash('1234'))
        )
        g.salaries_db.commit()
    return g.salaries_db

# Initialize admin users on app start
def init_admin_users():
    with app.app_context():
        salaries_db = get_salaries_db()
        salaries_db.execute('''
            CREATE TABLE IF NOT EXISTS AdminUser (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        # Add initial admin user
        salaries_db.execute(
            'INSERT OR IGNORE INTO AdminUser (username, password) VALUES (?, ?)',
            ('admin', generate_password_hash('1234'))
        )

        # Create the project_budgets table if it doesn't exist (without effective_date)
        salaries_db.execute('''
            CREATE TABLE IF NOT EXISTS project_budgets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL UNIQUE,
                budget REAL NOT NULL
            )
        ''')

        salaries_db.commit()

# Initialize admin users on app start
init_admin_users()

# Helper functions for authentication
def get_admin_user(username):
    salaries_db = get_salaries_db()
    return salaries_db.execute(
        'SELECT * FROM AdminUser WHERE username = ?', (username,)
    ).fetchone()

# Authentication decorator
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

@app.teardown_appcontext
def close_dbs(error):
    if hasattr(g, 'main_db'):
        g.main_db.close()
    if hasattr(g, 'salaries_db'):
        g.salaries_db.close()

# Salary management routes
@app.route('/salaries', methods=['GET', 'POST'])
@token_required
def salaries(current_user):
    main_db = get_main_db()
    salaries_db = get_salaries_db()
    
    if request.method == 'POST':
        user_id = request.form['user_id']
        salary = request.form['salary']
        effective_date = request.form['effective_date']
        
        salaries_db.execute('''
            INSERT INTO salaries (user_id, salary, effective_date)
            VALUES (?, ?, ?)
        ''', (user_id, salary, effective_date))
        salaries_db.commit()
        flash('Salary added successfully', 'success')
    
    salaries = salaries_db.execute('''
        SELECT salaries.id, salaries.user_id, salaries.salary, 
               salaries.effective_date, users.username 
        FROM salaries
        JOIN users ON salaries.user_id = users.id 
        ORDER BY salaries.effective_date DESC
    ''').fetchall()
    
    users = main_db.execute('SELECT * FROM users').fetchall()
    return render_template('salaries.html', salaries=salaries, users=users)

@app.route('/delete_salary/<int:salary_id>')
@token_required
def delete_salary(current_user, salary_id):
    salaries_db = get_salaries_db()
    salaries_db.execute('DELETE FROM salaries WHERE id = ?', (salary_id,))
    salaries_db.commit()
    flash('Salary record deleted successfully', 'success')
    return redirect(url_for('salaries'))

# Project budget management routes
@app.route('/project-budgets', methods=['GET', 'POST'])
@token_required
def project_budgets(current_user):
    main_db = get_main_db()
    salaries_db = get_salaries_db()
    
    if request.method == 'POST':
        project_id = request.form['project_id']
        budget = request.form['budget']
        
        # Upsert budget (update if exists, insert if new)
        salaries_db.execute('''
            INSERT INTO project_budgets (project_id, budget)
            VALUES (?, ?)
            ON CONFLICT(project_id) DO UPDATE SET budget = excluded.budget
        ''', (project_id, budget))
        salaries_db.commit()
        flash('Budget updated successfully', 'success')
    
    budgets = salaries_db.execute('''
        SELECT project_budgets.id, project_budgets.project_id, project_budgets.budget, 
               projects.name as project_name 
        FROM project_budgets
        JOIN main_db.projects ON project_budgets.project_id = projects.id 
    ''').fetchall()
    
    projects = main_db.execute('SELECT * FROM projects').fetchall()
    budget_dict = {budget['project_id']: budget['budget'] for budget in budgets}
    return render_template('project_budgets.html', 
                         budgets=budgets, 
                         projects=projects,
                         project_budgets_js=budget_dict)

@app.route('/edit_budget/<int:budget_id>', methods=['GET', 'POST'])
@token_required
def edit_budget(current_user, budget_id):
    salaries_db = get_salaries_db()
    main_db = get_main_db()
    
    budget = salaries_db.execute(
        'SELECT * FROM project_budgets WHERE id = ?', (budget_id,)
    ).fetchone()
    
    if request.method == 'POST':
        new_budget = request.form['budget']
        salaries_db.execute(
            'UPDATE project_budgets SET budget = ? WHERE id = ?',
            (new_budget, budget_id)
        )
        salaries_db.commit()
        flash('Budget updated successfully', 'success')
        return redirect(url_for('project_budgets'))
    
    projects = main_db.execute('SELECT * FROM projects').fetchall()
    return render_template('edit_budget.html', 
                         budget=budget, 
                         projects=projects)

@app.route('/delete_budget/<int:budget_id>')
@token_required
def delete_budget(current_user, budget_id):
    salaries_db = get_salaries_db()
    salaries_db.execute('DELETE FROM project_budgets WHERE id = ?', (budget_id,))
    salaries_db.commit()
    flash('Budget record deleted successfully', 'success')
    return redirect(url_for('project_budgets'))

# Project payment management routes
@app.route('/project-payments', methods=['GET', 'POST'])
@token_required
def project_payments(current_user):
    main_db = get_main_db()
    salaries_db = get_salaries_db()
    
    if request.method == 'POST':
        project_id = request.form['project_id']
        amount = request.form['amount']
        payment_date = request.form['payment_date']
        
        salaries_db.execute('''
            INSERT INTO project_payments (project_id, amount, payment_date)
            VALUES (?, ?, ?)
        ''', (project_id, amount, payment_date))
        salaries_db.commit()
        flash('Payment recorded successfully', 'success')
    
    payments = salaries_db.execute('''
        SELECT project_payments.id, project_payments.project_id, 
               project_payments.amount, project_payments.payment_date,
               projects.name as project_name 
        FROM project_payments
        JOIN main_db.projects ON project_payments.project_id = projects.id 
        ORDER BY project_payments.payment_date DESC
    ''').fetchall()
    
    projects = main_db.execute('SELECT * FROM projects').fetchall()
    return render_template('project_payments.html', payments=payments, projects=projects)

@app.route('/delete_payment/<int:payment_id>')
@token_required
def delete_payment(current_user, payment_id):
    salaries_db = get_salaries_db()
    salaries_db.execute('DELETE FROM project_payments WHERE id = ?', (payment_id,))
    salaries_db.commit()
    flash('Payment record deleted successfully', 'success')
    return redirect(url_for('project_payments'))

# Project costing route
@app.route('/project-costs')
@token_required
def project_costs(current_user):
    main_db = get_main_db()
    salaries_db = get_salaries_db()
    
    # Get sort parameters from request
    sort_by = request.args.get('sort', 'name')
    sort_order = request.args.get('order', 'asc')
    
    # Get all projects
    projects = main_db.execute('SELECT * FROM projects').fetchall()
    
    # Get all assignments
    assignments = main_db.execute('''
        SELECT user_projects.*, users.username, projects.name as project_name
        FROM user_projects
        JOIN users ON user_projects.user_id = users.id
        JOIN projects ON user_projects.project_id = projects.id
    ''').fetchall()
    
    # Get all salaries (latest salary per user)
    salaries = {}
    for row in salaries_db.execute('''
        SELECT s1.* 
        FROM salaries s1
        LEFT JOIN salaries s2 
            ON s1.user_id = s2.user_id 
            AND s1.effective_date < s2.effective_date
        WHERE s2.id IS NULL
    ''').fetchall():
        salaries[row['user_id']] = row['salary']
    
    # Get all project budgets (simple select since we removed effective_date)
    project_budgets = {}
    for row in salaries_db.execute('SELECT * FROM project_budgets').fetchall():
        project_budgets[row['project_id']] = row['budget']
    
    # Get all project payments
    project_payments = {}
    for row in salaries_db.execute('''
        SELECT project_id, SUM(amount) as total_payments 
        FROM project_payments 
        GROUP BY project_id
    ''').fetchall():
        project_payments[row['project_id']] = row['total_payments']
    
    # Calculate costs for each project
    project_costs = {}
    for project in projects:
        project_costs[project['id']] = {
            'name': project['name'],
            'status': project['status'],
            'current_cost': 0.0,
            'estimated_cost': 0.0,
            'budget': project_budgets.get(project['id'], 0.0),  # Default to 0 if no budget
            'payments': project_payments.get(project['id'], 0.0),  # Default to 0 if no payments
            'remaining_budget': project_budgets.get(project['id'], 0.0) - project_payments.get(project['id'], 0.0)
        }
    
    # Helper function to calculate business days
    def business_days(start, end):
        days = (end - start).days + 1
        full_weeks = days // 7
        extra_days = days % 7
        business_days = full_weeks * 5
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
    
    # Now we have the project_costs dictionary with current_cost, estimated_cost, and budget for each project
    # We can also calculate the variance for estimated and current if needed, but we'll do that in the template?
    # Or we can calculate here and pass. Let's do it here for consistency.

    # We'll create a list of project data for the template, adding variance fields.
    project_data = []
    for project_id, data in project_costs.items():
        # Calculate variances
        current_variance = data['budget'] - data['current_cost']
        estimated_variance = data['budget'] - data['estimated_cost']
        estimated_gain = data['budget'] - data['estimated_cost']
        pending_payment = data['budget'] - data['payments']
        
        project_data.append({
            'name': data['name'],
            'status': data['status'],
            'current_cost': data['current_cost'],
            'estimated_cost': data['estimated_cost'],
            'budget': data['budget'],
            'payments': data['payments'],
            'pending_payment': pending_payment,
            'estimated_gain': estimated_gain,
            'current_variance': current_variance,
            'estimated_variance': estimated_variance
        })
    
    # Sorting logic
    reverse_order = (sort_order == 'desc')
    
    if sort_by == 'pending_payment':
        project_data.sort(key=lambda x: x['pending_payment'], reverse=reverse_order)
    elif sort_by == 'estimated_gain':
        project_data.sort(key=lambda x: x['estimated_gain'], reverse=reverse_order)
    elif sort_by == 'name':
        project_data.sort(key=lambda x: x['name'], reverse=reverse_order)
    elif sort_by == 'status':
        project_data.sort(key=lambda x: x['status'], reverse=reverse_order)
    elif sort_by == 'current_cost':
        project_data.sort(key=lambda x: x['current_cost'], reverse=reverse_order)
    elif sort_by == 'estimated_cost':
        project_data.sort(key=lambda x: x['estimated_cost'], reverse=reverse_order)
    elif sort_by == 'budget':
        project_data.sort(key=lambda x: x['budget'], reverse=reverse_order)
    elif sort_by == 'payments':
        project_data.sort(key=lambda x: x['payments'], reverse=reverse_order)
    
    return render_template('project_costing.html', 
                         projects=project_data,
                         sort=sort_by,
                         order=sort_order)

# Login routes
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
            
            resp = make_response(redirect(url_for('project_costs')))
            resp.set_cookie('token', token)
            return resp
        
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('token', '', expires=0)
    return resp

# Admin Users management
@app.route('/admin-users', methods=['GET', 'POST'])
@token_required
def admin_users(current_user):
    salaries_db = get_salaries_db()
    
    if request.method == 'POST':
        if 'user_id' in request.form:  # Update existing user
            user_id = request.form['user_id']
            new_password = generate_password_hash(request.form['password'])
            salaries_db.execute('UPDATE AdminUser SET password = ? WHERE id = ?', (new_password, user_id))
        else:  # Create new user
            username = request.form['username']
            password = generate_password_hash(request.form['password'])
            try:
                salaries_db.execute('INSERT INTO AdminUser (username, password) VALUES (?, ?)', (username, password))
            except sqlite3.IntegrityError:
                return render_template('admin_users.html', error='Username already exists')
        salaries_db.commit()
    
    users = salaries_db.execute('SELECT * FROM AdminUser').fetchall()
    return render_template('admin_users.html', users=users)

if __name__ == '__main__':
    app.run(port=5001, debug=True) 