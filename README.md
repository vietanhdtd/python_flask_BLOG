python
## Create folder for project
# Create virtualenv
# Activate virtualenv
# install flask, sqlalchemy, migrate
'''
pip install flask
pip install flask-sqlalchemy
pip install flask-migrate
'''

# Create template folder
# Create main file (<Your app name>.py)

# <Your app name>.py
# import flask
# import flask_sqlalchemy
# import migrate

# create app

# config app
# config sqlalchemy


# create connection between app and sqlalchemy
db = # your code here

# create connection between app, sqlalchemy and migrate
migrate = # your code here

################################
## Define model here
################################

db.create_all()

################################
## Define route
################################

if __name__ == '__main__':
    # run app here with debug mode is True