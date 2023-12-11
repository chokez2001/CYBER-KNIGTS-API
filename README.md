# CYBER KNIGHTS API
This is a straightforward API implementation utilizing Flask and PostgreSQL. The API serves as the backend for a web application enabling users to access information from a database related to products and categories. It incorporates RBAC (Role-Based Access Control), basic rate limiting, and authentication. The database defines custom roles, namely user and admin, each with distinct permissions.
## Live Demo
[https://testingpage.online/](https://testingpage.online/)
## To start the project
If already have the conda environment and requirements ready for the server, go to step 5; otherwise, start from step 1
1. Install [conda](https://docs.conda.io/projects/conda/en/latest/user-guide/install/linux.html) with python version 3.10	
2. Create the environment using the command:
    ```
    conda env create --name ck-api python=3.10
    ```
3. Verify that the new environment was installed correctly:
    ```
    conda env list
    ```
4. Activate the environment: 
   ```
   conda activate ck-api
   ```

5. Install python requirements
   ```
   pip install -r requirements.txt
   ```
 - The actual requirements.txt file was generated using the command:
   ```
   pip freeze > requirements.txt
   ```
   and the file was updated manually to remove the packages that are not necessary for the project.

 - These are the packages in the requirements file:
   ```
   Flask==3.0.0
   Flask-Limiter==3.5.0
   Flask-Login==0.6.3
   Flask-SQLAlchemy==3.1.1
   python-dotenv==1.0.0
   Werkzeug==3.0.1
   psycopg-binary==2.9.9
   psycopg2==2.9.9
   cryptography==41.0.7
   ```
   
6. Copy env-example to file .env
   ```
   cp env-example .env
   ```
7. Config values into .env file

8. Run the server (u need to have the database running with the scheme created)
   ```
   python app.py
   ```       
## To add tables and data
To create tables in database
1. Run flask shell
   ```
   flask shell
   ```
2. Import the database instance 
   ```
   from api.db_models import db
   ```
3. Run the `create_all()` method to create related tables based on the model specified at `api.db_models.`
   If u need to drop the entire schema you can use drop_all().
   ```
   db.create_all()
   db.drop_all()
   ```
- If you want to create the database model manually, you can use the file `db/db_example.txt` as a template to generate the tables using classical PostgreSQL commands.

## Actual features
- Authentication: JWT Flask-Login.
- RBAC (Role Based Access Control): Flask-Login and the database.
- Basic rate Limiting: Flask-Limiter.
- HTTPS: Flask-Werkzeug self-signed certificate and key.
## Bandit Vulnerabilities Report 
In the root folder run the command:
```bash
bandit -r .
```
In our case, we have the following vulnerabilities:

![bandit](/images/bandit_result.png)

- The first vulnerability is about debug mode, so is simple to solve, just remove the parameter `debug=True` from the `app.run()` method in the `app.py` file. So we only need to use the debug mode in development environment, for things like hot reload and other features that help us in the development process. In production, we should never use debug mode, because it can expose sensitive information about the application and the server

- The second vulnerability pertains to hardcoding all bind addresses, which is relatively straightforward to address. The host parameter specifies the interfaces on which the application listens. By default, it listens on all interfaces. If the intention is to deploy the application on the internet, allowing it to listen on all interfaces is necessary. However, if the deployment is targeted for a local network, specifying the IP address of the hosting machine becomes an option. In our specific scenario, where the application is intended for internet deployment, we will maintain the host parameter in its default state.

## HTTPS Configuration
To configure HTTPS we need to generate a certificate and a key. We can use OpenSSL to generate them. 
Also you can use the parameter `ssl=adhoc` in the `app.run()` method in the `app.py` file to generate a self-signed certificate and key, but this is not recommended for production environments.
If the aplicaction is deployed in a web hosting probably you can configure the certificate and key in the hosting panel or it be configured automatically.


## Deploy to production
Deploy to Production
1. Follow instructions in [Deploy to production a Flask Aplication](https://flask.palletsprojects.com/en/2.2.x/tutorial/deploy/) 
   






   
